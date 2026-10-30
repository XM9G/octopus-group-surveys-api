

# octopus-group-surveys-api
a simple python script to get information from the internal octopus group surveys api

https://octopusgroup.com.au/

## warning ⚠️ 
 **this probably goes against octopus group's terms of service so be careful not to get your account banned. educational purposes only or whatever**

# setting up
in `login.json` put in your phone number and password as such

```
{
    "phone": "0412345678",
    "password": "somepassword"
}
```

make sure you put them in correctly cause i dont think i added error handling for inccorect credentials

# example
running the python script will print something like this:
```
===== Open Surveys =====
You have 2 open surveys.
Possible Earnings: $8.40
Total Time: 30 minutes

===== Balance =====
Current Balance: $28.12
Redeemable Balance: $20.00
Total Redeemed: $120.00
Time Required: $148.12

===== Survey Stats =====
Complete: 61
Screened Out: 18
QA Flagged: 3
Quota Exceeded: 6
Active: 2
```

you can use the code for any project of course this just demonstrates that it actually works
