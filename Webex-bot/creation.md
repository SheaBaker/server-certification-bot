### Step 1: Create the Webex Bot
1. Go to https://developer.webex.com and sign in with your Webex account.
2. Click your profile icon in the top right and select My Webex Apps.
3. Click Create a New App.
4. Select Create a Bot.
5. Fill in the bot details:
   - Bot Name: A friendly display name (e.g. My Alert Bot)
   - Bot Username: A unique username (e.g. myalertbot) — this becomes the bot's Webex address         (myalertbot@webex.bot)
   - Icon: Choose a default icon or upload a custom image
   - Description: A brief description of what the bot does
6. Click Add Bot.
7. Copy and save the Bot Access Token — this is only shown once. 


### Step 2: Create or Identify a Webex Space
1. Open the Webex app.
2. Create a new space or identify an existing one where the bot should post messages.
3. Add the bot to the space by searching for its username (e.g. myalertbot@webex.bot) and       inviting it as a member.
NOTE: The bot can only post to spaces it has been added to as a member.

### Step 3: Get the Room ID
The Room ID tells the bot which space to post messages to.
Command line:

bash
curl -s -H "Authorization: Bearer YOUR_BOT_TOKEN" \
  "https://webexapis.com/v1/rooms" | python3 -m json.tool | grep -A2 "YOUR_SPACE_NAME"

Save the id value — this is your room_id.
