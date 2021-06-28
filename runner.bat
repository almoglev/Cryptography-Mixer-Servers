start "receiver 1" python receiver.py password1 salt1 5000
start "receiver 2" python receiver.py password2 salt2 5001
start "sender 1" python sender.py 1
start "sender 2" python sender.py 2
start "mix 3" python mix.py 3
start "mix 2" python mix.py 2
start "mix 1" python mix.py 1