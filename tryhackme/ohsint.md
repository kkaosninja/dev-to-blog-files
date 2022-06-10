https://tryhackme.com/room/ohsint

*Are you able to use open source intelligence to solve this challenge?*

----

First step is download the task files. Task file looks like the standard Windows XP wallpaper

> Q1: What is this users avatar of?

What user? Let's look at the hint.

Hint says `exiftool is your friend. Who is the author of the image? Do they have any social media accounts?`

Hmm ok then. Let's run `exiftool` on the file and see if we can find any user info in it.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/6sr734tmqsos3pvd0y3u.png)

Interesting. Let's use a search engine if we can any social media accounts for this "OWoodflint".

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/1uvcsihy87hdgnw2s32f.png)

Awesome. We have found a Twitter and one of their GitHub repos.

Twitter -> https://twitter.com/OWoodflint
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/rq5j7y0u8zoeklrhk1ul.png)

Github -> https://github.com/OWoodfl1nt/people_finder
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/peehy7o5ciicf4u1jj8o.png)

Take note of ALL the important stuff you see in the above screenshots. They will come in handy at a later stage.

So, we can finally answer Q1 about the user's avatar, based on their Twitter profile pic. 

> A1: Cat

> Q2: What city is this person in?
> Hint: BSSID + Wigle.net

Once again, the question on its own does not make any sense to an OSINT noob like me. So had to take a look at the hint.

If you'll look at the Twitter account screenshot above, the second screenshot does have a BSSID(unique hardware MAC address for that particular wireless router). 

Now, looking at the hint, let's visit [wigle.net](https://wigle.net/). It seems to be a website which allows us to search user-contributed data on wireless networks around the world for our BSSID, and then pinpoint its location.

First, we'll need to register on the website before running a search.

Zoom out of the map, paste the BSSID in the BSSID search box, and then click on Filter. You will see a small ring around London. Keep zooming in, until you see the SSID name.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/9nospxnlabcx640e2woo.png)
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/fo9qw7k9p2tzliy1a16t.png)

So, now we can answer
> Q2: What city is this person in?
> A2: London

> Q3: Whats the SSID of the WAP he connected to?
> A3: UnileverWiFi

> Q4: What is his personal email address?
> A4: OWoodflint@gmail.com

Answer for Q4 found earlier in the README of their Github repo

> Q5: What site did you find his email address on?
> A5: GitHub

> Q6: Where has he gone on holiday?

Now, this was truly confusing. After running a couple more searches, finally found a link that appears to be their blog.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/v8rzcbv6fog7nmvmty1x.png)

Link to Blog => https://oliverwoodflint.wordpress.com/author/owoodflint/

Post content says "Im in New York right now, so I will update this site right away with new photos!". So probably on a vacation. 

> Q6: Where has he gone on holiday?
> A6: New York ( Found on his blog )

> Q7: What is this persons password?

Frankly I had no idea, until I went to that blog post again, and saw that weird string at the end of the blog post.

> Q7: What is this persons password?
> A7: pennYDr0pper.!

Thanks for reading. This was a fun goose chase, and a great introduction to OSINT.

Try the room at https://tryhackme.com/room/ohsint