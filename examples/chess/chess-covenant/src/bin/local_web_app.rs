use std::cell::RefCell;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::rc::Rc;

use chess_covenant::orchestrator::{
    ActualGameSnapshot, GameResult, MoveSpec, OffchainMessage, OffchainMessageKind, SigningPlayer, SubmittedTx, TxArena,
    TxOrchestrator,
};
use serde::{Deserialize, Serialize};

const ADDRESS: &str = "127.0.0.1:8080";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(ADDRESS)?;
    let mut app = LocalWebController::new()?;
    println!("Chess local web app listening on http://{ADDRESS}");

    for stream in listener.incoming() {
        let mut stream = stream?;
        if let Err(err) = handle_connection(&mut stream, &mut app) {
            let _ = write_response(&mut stream, 500, "text/plain; charset=utf-8", err.to_string().as_bytes());
        }
    }

    Ok(())
}

fn handle_connection(stream: &mut TcpStream, app: &mut LocalWebController) -> Result<(), Box<dyn std::error::Error>> {
    let request = read_http_request(stream)?;
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => write_response(stream, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes())?,
        ("GET", "/api/state") => {
            let body = serde_json::to_vec(&ApiResponse::ok(app.snapshot()))?;
            write_response(stream, 200, "application/json", &body)?;
        }
        ("POST", "/api/action") => {
            let action: ActionRequest = serde_json::from_slice(&request.body)?;
            let response = match app.handle_action(action) {
                Ok(()) => ApiResponse::ok(app.snapshot()),
                Err(err) => ApiResponse::err(err.to_string(), app.snapshot()),
            };
            let body = serde_json::to_vec(&response)?;
            write_response(stream, 200, "application/json", &body)?;
        }
        _ => write_response(stream, 404, "text/plain; charset=utf-8", b"not found")?,
    }
    Ok(())
}

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, Box<dyn std::error::Error>> {
    stream.set_read_timeout(Some(std::time::Duration::from_millis(250)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut header_end = None;
    let mut content_length = 0usize;

    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);

        if header_end.is_none() {
            header_end = find_subslice(&buf, b"\r\n\r\n");
            if let Some(end) = header_end {
                let header_text = String::from_utf8_lossy(&buf[..end]);
                for line in header_text.lines() {
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        content_length = value.trim().parse::<usize>()?;
                    }
                }
                if buf.len() >= end + 4 + content_length {
                    break;
                }
            }
        } else if let Some(end) = header_end {
            if buf.len() >= end + 4 + content_length {
                break;
            }
        }
    }

    let header_end = header_end.ok_or("malformed request: missing header terminator")?;
    let header = String::from_utf8(buf[..header_end].to_vec())?;
    let mut lines = header.lines();
    let request_line = lines.next().ok_or("malformed request line")?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_string();
    let path = parts.next().ok_or("missing path")?.to_string();
    let body_start = header_end + 4;
    let body = buf[body_start..body_start + content_length].to_vec();

    Ok(HttpRequest { method, path, body })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn write_response(stream: &mut TcpStream, status: u16, content_type: &str, body: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;
    Ok(())
}

struct LocalWebController {
    arena: Rc<RefCell<TxArena>>,
    white: TxOrchestrator,
    black: TxOrchestrator,
    notices: Vec<String>,
}

impl LocalWebController {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let arena = TxArena::shared()?;
        let white = TxOrchestrator::new("white", 0x41, arena.clone());
        let black = TxOrchestrator::new("black", 0x42, arena.clone());
        Ok(Self { arena, white, black, notices: Vec::new() })
    }

    fn handle_action(&mut self, action: ActionRequest) -> Result<(), Box<dyn std::error::Error>> {
        match action.action.as_str() {
            "register" => self.player_mut(action.actor.as_deref().ok_or("missing actor")?)?.register()?,
            "invite" => self.white.send_game_invite(&self.black)?,
            "accept_invite" => self.black.accept_game_invite(&self.white)?,
            "start_game" => self.white.start_game(&self.black)?,
            "move" => {
                let mv = parse_move_label(action.move_label.as_deref().ok_or("missing move label")?)?;
                self.player(action.actor.as_deref().ok_or("missing actor")?)?.submit_move(mv)?;
            }
            "surrender" => self.player(action.actor.as_deref().ok_or("missing actor")?)?.surrender()?,
            "request_settlement" => {
                let result = parse_result(action.result.as_deref().ok_or("missing result")?)?;
                let actor = action.actor.as_deref().ok_or("missing actor")?;
                self.player(actor)?.request_settlement(self.opponent(actor)?, result)?;
            }
            "settle" => {
                let result = parse_result(action.result.as_deref().ok_or("missing result")?)?;
                self.white.settle(&self.black, result)?;
            }
            "retire" => self.player(action.actor.as_deref().ok_or("missing actor")?)?.retire()?,
            other => return Err(format!("unknown action: {other}").into()),
        }
        self.flush_notices();
        Ok(())
    }

    fn snapshot(&self) -> AppSnapshot {
        let arena = self.arena.borrow();
        AppSnapshot {
            players: vec![player_view(&arena, &self.white.player, "white"), player_view(&arena, &self.black.player, "black")],
            game: arena.active_game_snapshot().map(game_view),
            history: arena.history().iter().map(history_view).collect(),
            notices: self.notices.clone(),
        }
    }

    fn flush_notices(&mut self) {
        let mut white_msgs = self.white.inbox();
        let mut black_msgs = self.black.inbox();
        self.notices.extend(white_msgs.drain(..).map(|msg| format_message("white", &msg)));
        self.notices.extend(black_msgs.drain(..).map(|msg| format_message("black", &msg)));
    }

    fn player(&self, actor: &str) -> Result<&TxOrchestrator, Box<dyn std::error::Error>> {
        match actor {
            "white" => Ok(&self.white),
            "black" => Ok(&self.black),
            _ => Err(format!("unknown actor: {actor}").into()),
        }
    }

    fn player_mut(&mut self, actor: &str) -> Result<&mut TxOrchestrator, Box<dyn std::error::Error>> {
        match actor {
            "white" => Ok(&mut self.white),
            "black" => Ok(&mut self.black),
            _ => Err(format!("unknown actor: {actor}").into()),
        }
    }

    fn opponent(&self, actor: &str) -> Result<&TxOrchestrator, Box<dyn std::error::Error>> {
        match actor {
            "white" => Ok(&self.black),
            "black" => Ok(&self.white),
            _ => Err(format!("unknown actor: {actor}").into()),
        }
    }
}

fn player_view(arena: &TxArena, player: &SigningPlayer, role: &str) -> PlayerView {
    match arena.player_account_snapshot(player) {
        Ok(account) => PlayerView {
            role: role.to_string(),
            registered: true,
            open_games: account.open_games,
            rating: account.rating,
            games: account.games,
            wins: account.wins,
            draws: account.draws,
            losses: account.losses,
        },
        Err(_) => {
            PlayerView { role: role.to_string(), registered: false, open_games: 0, rating: 0, games: 0, wins: 0, draws: 0, losses: 0 }
        }
    }
}

fn game_view(game: ActualGameSnapshot) -> GameView {
    GameView {
        turn: match game.turn {
            chess_covenant::orchestrator::Side::White => "white".to_string(),
            chess_covenant::orchestrator::Side::Black => "black".to_string(),
        },
        status: match game.status {
            0 => "live".to_string(),
            1 => "white_win".to_string(),
            2 => "black_win".to_string(),
            3 => "draw".to_string(),
            other => format!("status_{other}"),
        },
        board_rows: board_rows(&game.board),
        move_log: game.move_log,
    }
}

fn board_rows(board: &[u8]) -> Vec<String> {
    (0..8).rev().map(|y| (0..8).map(|x| piece_char(board[(y * 8 + x) as usize])).collect::<String>()).collect()
}

fn piece_char(piece: u8) -> char {
    match piece {
        0 => '.',
        1 => 'P',
        2 => 'N',
        3 => 'B',
        4 => 'R',
        5 => 'Q',
        6 => 'K',
        9 => 'p',
        10 => 'n',
        11 => 'b',
        12 => 'r',
        13 => 'q',
        14 => 'k',
        _ => '?',
    }
}

fn history_view(tx: &SubmittedTx) -> HistoryView {
    HistoryView { recipe_name: tx.recipe_name.to_string(), signer_names: tx.signer_names.clone() }
}

fn format_message(owner: &str, message: &OffchainMessage) -> String {
    match &message.kind {
        OffchainMessageKind::GameInvite { proposed_white, proposed_black } => {
            format!("{owner} inbox: invite {proposed_white} vs {proposed_black}")
        }
        OffchainMessageKind::InviteAccepted { white, black } => format!("{owner} inbox: invite accepted for {white} vs {black}"),
        OffchainMessageKind::GameStarted { white, black } => format!("{owner} inbox: game started for {white} vs {black}"),
        OffchainMessageKind::MoveNotice { actor, move_label, .. } => format!("{owner} inbox: {actor} played {move_label}"),
        OffchainMessageKind::SettlementRequest { result } => format!("{owner} inbox: settlement request {:?}", result),
        OffchainMessageKind::SettlementNotice { result } => format!("{owner} inbox: settlement complete {:?}", result),
    }
}

fn parse_move_label(label: &str) -> Result<MoveSpec, Box<dyn std::error::Error>> {
    let bytes = label.as_bytes();
    if bytes.len() != 4 && bytes.len() != 5 {
        return Err("move label must look like e2e4 or e7e8q".into());
    }
    let from_x = parse_file(bytes[0])?;
    let from_y = parse_rank(bytes[1])?;
    let to_x = parse_file(bytes[2])?;
    let to_y = parse_rank(bytes[3])?;
    let mut mv = MoveSpec::new(from_x, from_y, to_x, to_y);
    if bytes.len() == 5 {
        mv = MoveSpec::with_promotion(from_x, from_y, to_x, to_y, parse_promotion(bytes[4])?);
    }
    Ok(mv)
}

fn parse_file(ch: u8) -> Result<i64, Box<dyn std::error::Error>> {
    match ch {
        b'a'..=b'h' => Ok((ch - b'a') as i64),
        _ => Err("file must be a-h".into()),
    }
}

fn parse_rank(ch: u8) -> Result<i64, Box<dyn std::error::Error>> {
    match ch {
        b'1'..=b'8' => Ok((ch - b'1') as i64),
        _ => Err("rank must be 1-8".into()),
    }
}

fn parse_promotion(ch: u8) -> Result<i64, Box<dyn std::error::Error>> {
    match ch {
        b'n' | b'N' => Ok(2),
        b'b' | b'B' => Ok(3),
        b'r' | b'R' => Ok(4),
        b'q' | b'Q' => Ok(5),
        _ => Err("promotion must be n, b, r, or q".into()),
    }
}

fn parse_result(value: &str) -> Result<GameResult, Box<dyn std::error::Error>> {
    match value {
        "white_win" => Ok(GameResult::WhiteWin),
        "black_win" => Ok(GameResult::BlackWin),
        "draw" => Ok(GameResult::Draw),
        _ => Err("result must be white_win, black_win, or draw".into()),
    }
}

#[derive(Deserialize)]
struct ActionRequest {
    action: String,
    actor: Option<String>,
    move_label: Option<String>,
    result: Option<String>,
}

#[derive(Serialize)]
struct ApiResponse {
    ok: bool,
    error: Option<String>,
    state: AppSnapshot,
}

impl ApiResponse {
    fn ok(state: AppSnapshot) -> Self {
        Self { ok: true, error: None, state }
    }

    fn err(error: String, state: AppSnapshot) -> Self {
        Self { ok: false, error: Some(error), state }
    }
}

#[derive(Serialize)]
struct AppSnapshot {
    players: Vec<PlayerView>,
    game: Option<GameView>,
    history: Vec<HistoryView>,
    notices: Vec<String>,
}

#[derive(Serialize)]
struct PlayerView {
    role: String,
    registered: bool,
    open_games: i64,
    rating: i64,
    games: i64,
    wins: i64,
    draws: i64,
    losses: i64,
}

#[derive(Serialize)]
struct GameView {
    turn: String,
    status: String,
    board_rows: Vec<String>,
    move_log: Vec<String>,
}

#[derive(Serialize)]
struct HistoryView {
    recipe_name: String,
    signer_names: Vec<String>,
}

const INDEX_HTML: &str = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Chess Covenant Local Arena</title>
  <style>
    body { font-family: Georgia, serif; margin: 24px; background: #f4f0e8; color: #1f1a17; }
    h1, h2 { margin-bottom: 0.3rem; }
    .row { display: flex; gap: 24px; align-items: flex-start; flex-wrap: wrap; }
    .card { background: #fffaf2; border: 1px solid #d8c8ae; padding: 16px; border-radius: 12px; min-width: 280px; }
    button, select, input { padding: 8px 10px; margin: 4px 0; font: inherit; }
    pre { margin: 0; font-size: 20px; line-height: 1.2; }
    ul { margin-top: 0.5rem; }
    .error { color: #9d1c1c; min-height: 1.5rem; }
    .ok { color: #245b2a; min-height: 1.5rem; }
  </style>
</head>
<body>
  <h1>Chess Covenant Local Arena</h1>
  <p>Interactive local game UI over the shared tx-driven orchestrator.</p>
  <div id="status" class="ok"></div>
  <div id="error" class="error"></div>
  <div class="row">
    <div class="card">
      <h2>Setup</h2>
      <button onclick="act({action:'register', actor:'white'})">Register White</button><br/>
      <button onclick="act({action:'register', actor:'black'})">Register Black</button><br/>
      <button onclick="act({action:'invite'})">White Sends Invite</button><br/>
      <button onclick="act({action:'accept_invite'})">Black Accepts Invite</button><br/>
      <button onclick="act({action:'start_game'})">Start Game</button>
    </div>
    <div class="card">
      <h2>Moves</h2>
      <select id="moveActor">
        <option value="white">white</option>
        <option value="black">black</option>
      </select>
      <input id="moveLabel" value="e2e4" />
      <button onclick="submitMove()">Submit Move</button><br/>
      <select id="surrenderActor">
        <option value="white">white</option>
        <option value="black">black</option>
      </select>
      <button onclick="submitSurrender()">Surrender</button>
    </div>
    <div class="card">
      <h2>Settlement</h2>
      <select id="settlementActor">
        <option value="white">white</option>
        <option value="black">black</option>
      </select>
      <select id="settlementResult">
        <option value="white_win">white win</option>
        <option value="black_win">black win</option>
        <option value="draw">draw</option>
      </select><br/>
      <button onclick="requestSettlement()">Request Settlement</button>
      <button onclick="settle()">Settle</button><br/>
      <select id="retireActor">
        <option value="white">white</option>
        <option value="black">black</option>
      </select>
      <button onclick="retirePlayer()">Retire</button>
    </div>
  </div>
  <div class="row" style="margin-top: 24px;">
    <div class="card">
      <h2>Players</h2>
      <div id="players"></div>
    </div>
    <div class="card">
      <h2>Board</h2>
      <pre id="board">No active game</pre>
      <div id="gameMeta"></div>
    </div>
    <div class="card">
      <h2>Notices</h2>
      <ul id="notices"></ul>
    </div>
    <div class="card">
      <h2>Tx History</h2>
      <ul id="history"></ul>
    </div>
  </div>
  <script>
    async function fetchState() {
      const res = await fetch('/api/state');
      const data = await res.json();
      render(data.state);
    }
    async function act(payload) {
      document.getElementById('error').textContent = '';
      const res = await fetch('/api/action', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      render(data.state);
      if (data.ok) {
        document.getElementById('status').textContent = 'Action applied';
      } else {
        document.getElementById('status').textContent = '';
        document.getElementById('error').textContent = data.error;
      }
    }
    function submitMove() {
      act({
        action: 'move',
        actor: document.getElementById('moveActor').value,
        move_label: document.getElementById('moveLabel').value
      });
    }
    function submitSurrender() {
      act({
        action: 'surrender',
        actor: document.getElementById('surrenderActor').value
      });
    }
    function requestSettlement() {
      act({
        action: 'request_settlement',
        actor: document.getElementById('settlementActor').value,
        result: document.getElementById('settlementResult').value
      });
    }
    function settle() {
      act({
        action: 'settle',
        result: document.getElementById('settlementResult').value
      });
    }
    function retirePlayer() {
      act({
        action: 'retire',
        actor: document.getElementById('retireActor').value
      });
    }
    function render(state) {
      document.getElementById('players').innerHTML = state.players.map(p =>
        `<div><strong>${p.role}</strong>: registered=${p.registered}, rating=${p.rating}, open=${p.open_games}, W/D/L=${p.wins}/${p.draws}/${p.losses}</div>`
      ).join('');
      if (state.game) {
        document.getElementById('board').textContent = state.game.board_rows.join('\n');
        document.getElementById('gameMeta').textContent = `turn=${state.game.turn}, status=${state.game.status}, moves=${state.game.move_log.join(', ')}`;
      } else {
        document.getElementById('board').textContent = 'No active game';
        document.getElementById('gameMeta').textContent = '';
      }
      document.getElementById('notices').innerHTML = state.notices.map(n => `<li>${n}</li>`).join('');
      document.getElementById('history').innerHTML = state.history.map(h => `<li>${h.recipe_name} [${h.signer_names.join(', ')}]</li>`).join('');
    }
    fetchState();
  </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_can_drive_a_short_local_game() {
        let mut app = LocalWebController::new().expect("controller builds");
        app.handle_action(ActionRequest { action: "register".into(), actor: Some("white".into()), move_label: None, result: None })
            .expect("white registers");
        app.handle_action(ActionRequest { action: "register".into(), actor: Some("black".into()), move_label: None, result: None })
            .expect("black registers");
        app.handle_action(ActionRequest { action: "invite".into(), actor: None, move_label: None, result: None })
            .expect("invite works");
        app.handle_action(ActionRequest { action: "accept_invite".into(), actor: None, move_label: None, result: None })
            .expect("accept works");
        app.handle_action(ActionRequest { action: "start_game".into(), actor: None, move_label: None, result: None })
            .expect("start works");
        app.handle_action(ActionRequest {
            action: "move".into(),
            actor: Some("white".into()),
            move_label: Some("e2e4".into()),
            result: None,
        })
        .expect("white move works");
        app.handle_action(ActionRequest {
            action: "move".into(),
            actor: Some("black".into()),
            move_label: Some("g8f6".into()),
            result: None,
        })
        .expect("black move works");
        app.handle_action(ActionRequest {
            action: "move".into(),
            actor: Some("white".into()),
            move_label: Some("f1c4".into()),
            result: None,
        })
        .expect("white bishop move works");
        app.handle_action(ActionRequest { action: "surrender".into(), actor: Some("black".into()), move_label: None, result: None })
            .expect("surrender works");
        app.handle_action(ActionRequest {
            action: "request_settlement".into(),
            actor: Some("black".into()),
            move_label: None,
            result: Some("white_win".into()),
        })
        .expect("request works");
        app.handle_action(ActionRequest { action: "settle".into(), actor: None, move_label: None, result: Some("white_win".into()) })
            .expect("settle works");

        let snapshot = app.snapshot();
        assert!(snapshot.game.is_none());
        assert!(snapshot.notices.iter().any(|n| n.contains("e2e4")));
        assert!(snapshot.notices.iter().any(|n| n.contains("settlement complete")));
    }

    #[test]
    fn parses_promotion_move_label() {
        let mv = parse_move_label("e7e8q").expect("promotion parses");
        assert_eq!(mv.from_x, 4);
        assert_eq!(mv.from_y, 6);
        assert_eq!(mv.to_x, 4);
        assert_eq!(mv.to_y, 7);
        assert_eq!(mv.promo_piece, 5);
    }
}
