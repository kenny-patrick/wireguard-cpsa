(herald "wireguard protocol handshake"
	 (algebra diffie-hellman))

(defprotocol handshake diffie-hellman
	(defrole peer
		(vars (s_self e_self rndx) (s_other e_other expt) (self other name) (n data))
		(trace
			;; We start with the two static (long-term) keys
			(recv (enc "sig" (exp (gen) s_self) self (privk self)))
			(recv (enc "sig" (exp (gen) s_other) other (privk other)))
			;; Now we exchange ephemeral keys
			(send (exp (gen) e_self))
			(recv (exp (gen) e_other))
			;; Now we can send data
			(send n))
			(uniq-gen e_self))
	;; simulates the creation of the static (long-term) keys
	(defrole static-sign
		(vars (self name) (s_self rndx))
		(trace
			(send (enc "sig" (exp (gen) s_self) self (privk self))))
		(uniq-gen s_self)
	(comment "Wireguard handshake")))

;; Exchange between two peers, A and B
(defskeleton handshake
	(vars (eA sA rndx) (A B name))
	(defstrand peer 5 (e_self eA) (s_self sA) (self A) (other B))
	(non-orig sA)
	(comment "Initiator point of view"))
