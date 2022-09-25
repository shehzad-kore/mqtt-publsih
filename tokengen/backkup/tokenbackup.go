package main

import (
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	MQTT "github.com/eclipse/paho.mqtt.golang"
	jwt "github.com/golang-jwt/jwt"
	"io/ioutil"
	"log"
	"time"
)

var (
	bridge = struct {
		host *string
		port *string
	}{
		flag.String("mqtt_host", "mqtt.googleapis.com", "MQTT Bridge Host"),
		flag.String("mqtt_port", "1883", "MQTT Bridge Port"),
	}
	projectID  = flag.String("project", "my-iot-356305", "GCP Project ID")
	region     = flag.String("region", "asia-east1", "GCP Region")
	registryID = flag.String("registry", "broker_test", "Cloud IoT Registry ID (short form)")
	deviceID   = flag.String("device", "shaiz_test", "Cloud IoT Core Device ID")

	//certsCA    = flag.String("ca_certs", "https://pki.google.com/roots.pem", "Download https://pki.google.com/roots.pem")
	privateKey = flag.String("private_key", "certs/device1.key", "Path to private key file")
	publicKey  = flag.String("public_key", "certs/device1.crt", "Path to public key file")
)

// Verify a JWT token using an RSA public key
func VerifyJWTRSA(token, publicKey string) (bool, *jwt.Token, error) {
	var parsedToken *jwt.Token
	// parse token
	state, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// ensure signing method is correct
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New("unknown signing method")
		}
		parsedToken = token
		// verify
		key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(publicKey))
		if err != nil {
			return nil, err
		}
		return key, nil
	})
	if err != nil {
		return false, &jwt.Token{}, err
	}
	if !state.Valid {
		fmt.Println("invalid jwt token")
		return false, &jwt.Token{}, errors.New("invalid jwt token")
	}
	return true, parsedToken, nil
}
func createJWT(projectID string, privateKeyPath string, algorithm string, expiration time.Duration) (string, error) {
	claims := jwt.StandardClaims{
		Audience:  projectID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute * expiration).Unix(),
	}
	keyBytes, err := ioutil.ReadFile(privateKeyPath)
	keyBytesPub, err := ioutil.ReadFile(*publicKey)
	if err != nil {
		return "", err
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod(algorithm), claims)
	switch algorithm {
	case "RS256":
		privKey, _ := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
		tokenStr, err := token.SignedString(privKey)
		fmt.Println(tokenStr)
		if err != nil {
			panic(err)
		}
		b, _, err := VerifyJWTRSA(tokenStr, string(keyBytesPub))
		if b == false {
			fmt.Println("token verification failed")
			panic(err)
		}
		return token.SignedString(privKey)
	case "ES256":
		privKey, _ := jwt.ParseECPrivateKeyFromPEM(keyBytes)
		return token.SignedString(privKey)
	}
	return "", errors.New("Cannot find JWT algorithm. Specify 'ES256' or 'RS256'")
}
func main() {
	log.Println("[main] Entered")
	log.Println("[main] Flags")
	flag.Parse()
	log.Println("[main] Loading Google's roots")
	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile("googleroots.pem")
	if err == nil {
		certpool.AppendCertsFromPEM(pemCerts)
	} else {
		panic(err)
	}
	log.Println("[main] Creating TLS Config")
	/*config := &tls.Config{
	    RootCAs:    certpool,
	    ClientAuth: tls.NoClientCert,
	    ClientCAs:  nil,
	}*/
	clientID := fmt.Sprintf("projects/%v/locations/%v/registries/%v/devices/%v",
		*projectID,
		*region,
		*registryID,
		*deviceID,
	)
	log.Println("[main] Creating MQTT Client Options")
	opts := MQTT.NewClientOptions()
	broker := fmt.Sprintf("ssl://%v:%v", *bridge.host, *bridge.port)
	log.Printf("[main] Broker '%v'", broker)
	//opts.AddBroker(broker)
	opts.AddBroker("tls://mqtt.googleapis.com:8883")
	//opts.SetClientID(clientID).SetTLSConfig(config)
	opts.SetClientID(clientID)
	opts.SetUsername("unused")
	opts.SetProtocolVersion(4)
	/*token := jwt.New(jwt.SigningMethodRS256)
	  token.Claims = jwt.StandardClaims{
	      Audience:  *projectID,
	      IssuedAt:  time.Now().Unix(),
	      ExpiresAt: time.Now().Add(24 * time.Hour).Unix(),
	  }*/
	log.Println("[main] Load Private Key")
	/*keyBytes, err := ioutil.ReadFile(*privateKey)
	  if err != nil {
	      log.Fatal(err)
	  }*/
	log.Println("[main] Parse Private Key")
	/*key, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	  if err != nil {
	      log.Fatal(err)
	  }*/
	log.Println("[main] Sign String")
	tokenString, err := createJWT(*projectID, *privateKey, "RS256", 600) //token.SignedString(key)
	if err != nil {
		log.Fatal(err)
	}
	opts.SetPassword(tokenString)
	// Incoming
	opts.SetDefaultPublishHandler(func(client MQTT.Client, msg MQTT.Message) {
		fmt.Printf("[handler] Topic: %v\n", msg.Topic())
		fmt.Printf("[handler] Payload: %v\n", msg.Payload())
	})
	log.Println("[main] MQTT Client Connecting")
	client := MQTT.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal("token error: ", token.Error())
	}
	topic := struct {
		config    string
		telemetry string
		state     string
	}{
		config:    fmt.Sprintf("/devices/%v/config", *deviceID),
		state:     fmt.Sprintf("/devices/%v/state", *deviceID),
		telemetry: fmt.Sprintf("/devices/%v/event", *deviceID),
	}
	log.Println("[main] Creating Subscription")
	client.Subscribe(topic.config, 0, nil)
	log.Println("[main] Publishing Messages")
	for i := 0; i < 1; i++ {
		log.Printf("[main] Publishing Message #%d", i)
		token := client.Publish(
			topic.state,
			1,
			false,
			fmt.Sprintf("Message: %d", i))
		token.WaitTimeout(5 * time.Second)
		print(token.Error())
		print(token.Wait())
	}
	log.Println("[main] MQTT Client Disconnecting")
	client.Disconnect(250)
	log.Println("[main] Done")
}
