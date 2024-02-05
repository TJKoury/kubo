package rpc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"

	"github.com/ipfs/boxo/ipns"
	"github.com/ipfs/boxo/path"
	iface "github.com/ipfs/kubo/core/coreiface"
	caopts "github.com/ipfs/kubo/core/coreiface/options"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multibase"
)

type KeyAPI HttpApi

type key struct {
	name      string
	publicKey string
	pid       peer.ID
	path      path.Path
}

func newKey(name string, pid peer.ID, publicKey crypto.PubKey) (*key, error) {
	p, err := path.NewPath("/ipns/" + ipns.NameFromPeer(pid).String())
	if err != nil {
		return nil, err
	}

	pubKeyBase64 := "" // Default to an empty string if no public key is provided
	if publicKey != nil {
		// Marshal the public key to bytes only if it's provided
		pubKeyBytes, err := crypto.MarshalPublicKey(publicKey)
		if err != nil {
			return nil, err
		}

		// Encode the public key bytes to a base64 string
		pubKeyBase64 = base64.StdEncoding.EncodeToString(pubKeyBytes)
	}

	return &key{
		name:      name,
		pid:       pid,
		publicKey: pubKeyBase64, // Set to the base64-encoded public key or an empty string
		path:      p,
	}, nil
}

func (k *key) PublicKey() string {
	return k.publicKey
}

func (k *key) Path() path.Path {
	return k.path
}

func (k *key) ID() peer.ID {
	return k.pid
}

type keyOutput struct {
	Name string
	Id   string
}

func (api *KeyAPI) Generate(ctx context.Context, name string, opts ...caopts.KeyGenerateOption) (iface.Key, error) {
	options, err := caopts.KeyGenerateOptions(opts...)
	if err != nil {
		return nil, err
	}

	var out keyOutput
	err = api.core().Request("key/gen", name).
		Option("type", options.Algorithm).
		Option("size", options.Size).
		Exec(ctx, &out)
	if err != nil {
		return nil, err
	}

	return newKey(out.Name, out.Id)
}

func (api *KeyAPI) Rename(ctx context.Context, oldName string, newName string, opts ...caopts.KeyRenameOption) (iface.Key, bool, error) {
	options, err := caopts.KeyRenameOptions(opts...)
	if err != nil {
		return nil, false, err
	}

	var out struct {
		Was       string
		Now       string
		Id        string
		Overwrite bool
	}
	err = api.core().Request("key/rename", oldName, newName).
		Option("force", options.Force).
		Exec(ctx, &out)
	if err != nil {
		return nil, false, err
	}

	key, err := newKey(out.Now, out.Id)
	if err != nil {
		return nil, false, err
	}

	return key, out.Overwrite, err
}

func (api *KeyAPI) List(ctx context.Context) ([]iface.Key, error) {
	var out struct {
		Keys []keyOutput
	}
	if err := api.core().Request("key/list").Exec(ctx, &out); err != nil {
		return nil, err
	}

	res := make([]iface.Key, len(out.Keys))
	for i, k := range out.Keys {
		key, err := newKey(k.Name, k.Id)
		if err != nil {
			return nil, err
		}
		res[i] = key
	}

	return res, nil
}

func (api *KeyAPI) Self(ctx context.Context) (iface.Key, error) {
	var id struct{ ID string }
	if err := api.core().Request("id").Exec(ctx, &id); err != nil {
		return nil, err
	}

	return newKey("self", id.ID)
}

func (api *KeyAPI) Remove(ctx context.Context, name string) (iface.Key, error) {
	var out struct {
		Keys []keyOutput
	}
	if err := api.core().Request("key/rm", name).Exec(ctx, &out); err != nil {
		return nil, err
	}
	if len(out.Keys) != 1 {
		return nil, errors.New("got unexpected number of keys back")
	}

	return newKey(out.Keys[0].Name, out.Keys[0].Id)
}

func (api *KeyAPI) core() *HttpApi {
	return (*HttpApi)(api)
}

func (api *KeyAPI) Sign(ctx context.Context, name string, data []byte) (iface.Key, []byte, error) {
	var out struct {
		Key       keyOutput
		Signature string
	}

	err := api.core().Request("key/sign").
		Option("key", name).
		FileBody(bytes.NewReader(data)).
		Exec(ctx, &out)
	if err != nil {
		return nil, nil, err
	}

	key, err := newKey(out.Key.Name, out.Key.Id)
	if err != nil {
		return nil, nil, err
	}

	_, signature, err := multibase.Decode(out.Signature)
	if err != nil {
		return nil, nil, err
	}

	return key, signature, nil
}

func (api *KeyAPI) Verify(ctx context.Context, keyOrName string, signature, data []byte) (iface.Key, bool, error) {
	var out struct {
		Key            keyOutput
		SignatureValid bool
	}

	err := api.core().Request("key/verify").
		Option("key", keyOrName).
		Option("signature", toMultibase(signature)).
		FileBody(bytes.NewReader(data)).
		Exec(ctx, &out)
	if err != nil {
		return nil, false, err
	}

	key, err := newKey(out.Key.Name, out.Key.Id)
	if err != nil {
		return nil, false, err
	}

	return key, out.SignatureValid, nil
}
