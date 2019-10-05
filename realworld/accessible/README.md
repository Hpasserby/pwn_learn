## README

The patch should apply to chromium commit `0c52497b2d30fadfc5b04addb8315e9f49a15baa` (v8 commit `eefa087eca9c54bdb923b8f5e5e14265f6970b22`).

Submit your URL to the challenge submission panel, and I will be doing the following:

* I will create a container with the browser and flag (at /flag) inside.
* I will run the browser with command: `chromium-browser --headless --no-sandbox --disable-gpu --virtual-time-budget=60000 $URL`.
* I will wait until the browser dies or the container times out (60 seconds).
* I will destroy the container.

