set -x  # uncomment to debug
DIR="../../dev/web-inspector"
python3 RunLeakDetector.py ${DIR}/210528-login-100k_no_action_nyc > no_action_nyc_leak.log
# python3 RunLeakDetector.py ${DIR}/210604-login-100k-CMP_accept_all_nyc > accept_all_nyc_leak.log
# python3 RunLeakDetector.py ${DIR}/210604-login-100k-CMP_reject_all_nyc > reject_all_nyc_leak.log

# python3 RunLeakDetector.py ${DIR}/210528-login-100k_no_action_fra > no_action_fra_leak.log
# python3 RunLeakDetector.py ${DIR}/210604-login-100k-CMP_accept_all_fra > accept_all_fra_leak.log
# python3 RunLeakDetector.py ${DIR}/210604-login-100k-CMP_reject_all_fra > reject_all_fra_leak.log
