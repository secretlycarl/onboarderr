# onboarderr
Self-hosted user onboarding site for Plex and Audiobookshelf server owners

# Introducing Onboarderr

PLEX ONBOARDINF SS

Onboarderr serves as a sort of advertisement site for a host's Plex and Audiobookshelf servers, with instructions for new users (and a few admin tools).

It's not exactly plug and play, as I tried to make it customizable for each host and there's a lot to tweak before sharing it with users. Please read the readme!

As someone who's never made a website before, I made this to accomplish a few goals - 

- Learn about HTML, CSS, websites in general, and self-hosting

- To improve on a few "new user setup" guides I've seen for Plex

- To have a more enticing method of having friends join my Plex instead of just "sign up and I'll send a link"

- Give me something constructive to do while unemployed lol


Admittedly, most of the code was written by AI (ChatGPT, Gemini, Cursor). 

I did all of the layout, copywriting/instructions, collected and edited screenshots, and came up with this whole thing.


# Features

Up-to-date (as of writing this) instructions for new users to join the host's Plex/Audiobookshelf and get the best streaming experience

Content from Plex and Audiobookshelf populates sections of the website (poster carousels, media lists)

Optional Discord notifications for when people request access

Admin dashboard


# Screenshots

Setup

Plex Onboarding

Audiobookshelf Onboarding

Media Lists

Admin Page




# Requirements

Python (3.10? idk) on your system's PATH

Plex Media Server

A way to host domains and make them public to the internet (if you're new to self-hosting websites, try tailscale with tailscale funnel. simple and free. I use Cloudflared now to handle a few URLs I want to make public)

I tested this on my Windows 11 machine, and someone got it going on a Mac host too.


# Optional Requirements

[Audiobookshelf](https://www.audiobookshelf.org/) Server and public URL to share with users

[Pulsarr](https://github.com/jamcalli/Pulsarr) - Per-user content requests integrated w/ Sonarr & Radarr via Plex watchlist
- Pulsarr is able to push "media added" notifications through the Plex mobile app via Tautulli integration. Works fine for movies, but does not handle every new episode of shows. Hence the next one-

[Tautulli](https://github.com/Tautulli/Tautulli) - Per-user individual "episode/audiobook added" notifications on Discord

Discord - to handle certain admin & user notifications

# First Time Install

	git clone [repo url]

	cd [folder]

Before you run the script, set these variables in .env:

```SITE_PASSWORD``` - for guests

```ADMIN_PASSWORD``` - for you

```DRIVES``` - Local drives that will have storage bars on the admin page later. TEST EMPTY

The other variables are filled in with a form that shows on first startup.

Create and activate a venv, I prefer to use conda. Then do

	pip install -r requirements.txt

	python app.py

If you used a venv, you need to activate it every time you run the script/website. Or make a ```.ps1``` or ```.bat``` with both commands

(When ready to share with users) activate your tailscale funnel, cloudflare tunnel, or bingle tube

I set the python script that handles everything to work on port ```10000```. You can change this at the bottom of ```app.py```.

```debug=True``` at the bottom of ```app.py``` is on for testing, otherwise html changes don't update on reload. might be bad to keep ```True``` forever?

go to ```http://127.0.0.1:10000```

First time setup will show, where you enter all the needed variables. The library descriptions you write are saved to ```library_notes.json```.

The way I set it up, it pulls artwork from my Plex libraries to show in the carousels. I have an audiobook library with the same content as my ABS server so it was easiest for me to just use Plex to pull those images instead of new logic for ABS.

You can tweak any of this in the services/admin page later

After submission, restart the script to apply the new ```.env``` and go to Login (on windows, ctrl+c in terminal window, then ```python app.py``` again)

```ADMIN_PASSWORD``` will take you to services page, but you can browse the others from the links at the top.

```SITE_PASSWORD``` will not allow access to admin page (at least I think I set that right, works in testing)


# !!! Per-Host Tweaks !!!

Once you're through setup and can see the site running, look through all the copy/instructions/etc I wrote and change what you want in the HTMLs.

Pick a new ```--accent``` color in the CSS, this will change all instances of COLOR in the HTML

Make a new logo and wordmark, I made the ones it comes with quickly with these sites -

Simple vector editor - https://vectorink.io/app/canvas

Wordmark Generator (make output text as big as slider allows) - https://fontmeme.com/netflix-font/

Section 5 in ```onboarding.html``` only applies if you have Pulsarr set up.

Section 7 in ```onboarding.html``` is personalized to me, you should rewrite it

I wrote "...ask me about my discord" in the body a few times. I have Tautulli on my server and can make separate channels for users to be notified about content they're interested in. Remove those mentions if you don't have that.

Change the Audiobookshelf server URL in audiobookshelf.html (line 83) if you host it and want to share

Edit the ```services = [``` list in ```app.py``` starting at line 338, to have the services you want to populate the admin page.



# Future goals

I've never made a project this complex, or had a project this many people were interested in, so I'm not clear on how the future development for this will go. I have some ideas to make it better, but getting this all set up in a way that it's customizable and not just for my machine only was a beast itself.

So you want to improve on this, please do! Fork, pull request, whatever.

Some improvements I might work on after publishing the initial version -

- Improve layout, make more modern/adaptive, especially on mobile. My CSS implementation of mobile device detection, and how it changes elements for mobile, is crude at the moment.

- Better library image handling (currently pulls 25 random posters for each category on startup, i like this personally but maybe it could be changed to grab a new set on an interval)

- Fix looping of carousels (now they just sorta reset to initial pos and keep going that way)

- Rate limiting/better site security

- Way to run it in the background - this is probably possible already but idk that much about self hosting. for testing and sharing with a few friends I just leave the terminal window open with the funnel and script active



# Thank You!

Thanks for your interest in my project! I hope you find it useful. If you want to give me a tip for putting this all together - 

https://ko-fi.com/secretlycarl#linkModal
