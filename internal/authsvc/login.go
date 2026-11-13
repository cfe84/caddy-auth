package authsvc

const loginStyles = `
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1.5rem; background: #f3f5f8; color: #1f2937; font-family: system-ui, sans-serif; }
main { width: 100%; max-width: 24rem; padding: 2rem; background: white; border: 1px solid #e2e8f0; border-radius: 1rem; box-shadow: 0 8px 30px #1f29370a; }
h1 { margin: 0 0 .5rem; font-size: 1.75rem; }
p { margin: 0 0 1.75rem; color: #526071; line-height: 1.5; }
form { display: grid; gap: 1.25rem; }
label { display: grid; gap: .5rem; font-size: .95rem; font-weight: 600; }
input, button { width: 100%; padding: .8rem; border-radius: .5rem; font: inherit; }
input { border: 1px solid #94a3b8; background: white; color: inherit; }
button { border: 0; background: #1d4ed8; color: white; font-weight: 600; cursor: pointer; }
button:hover { background: #1e40af; }
input:focus-visible, button:focus-visible { outline: 3px solid #2563eb; outline-offset: 3px; }
`

const loginPage = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>%s</style>
</head>
<body>
<main>
<h1>Sign in</h1>
<p>Enter your credentials to continue.</p>
<form method="post" action="/login">
<input type="hidden" name="csrf" value="%s">
<input type="hidden" name="request" value="%s">
<label>Username <input name="username" autocomplete="username" required></label>
<label>Password <input type="password" name="password" autocomplete="current-password" required></label>
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>`
