package vmware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const restMime = "application/vnd.vmware.vmw.rest-v1+json"

// Rest is a minimal client for the VMware Workstation/Fusion REST API (vmrest).
type Rest struct {
	URL, User, Password string
	http                *http.Client
}

func NewRest(url, user, password string) *Rest {
	if url == "" {
		url = "http://127.0.0.1:8697"
	}
	return &Rest{URL: strings.TrimRight(url, "/"), User: user, Password: password, http: &http.Client{Timeout: 30 * time.Second}}
}

type Vmnet struct {
	Name   string `json:"name"`
	Type   string `json:"type"` // hostOnly | nat | bridged
	DHCP   string `json:"dhcp"`
	Subnet string `json:"subnet"`
	Mask   string `json:"mask"`
}

func (r *Rest) do(method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.URL+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", restMime)
	if body != nil {
		req.Header.Set("Content-Type", restMime)
	}
	if r.User != "" {
		req.SetBasicAuth(r.User, r.Password)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return fmt.Errorf("vmrest %s %s: %v (is `vmrest` running? cloudseed starts it for you; configure once with `vmrest -C`)", method, path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		return fmt.Errorf("vmrest rejected the credentials (set vmrest_user/vmrest_password or VMREST_USER/VMREST_PASSWORD to what you gave `vmrest -C`)")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vmrest %s %s: HTTP %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (r *Rest) ListVmnets() ([]Vmnet, error) {
	var res struct {
		Vmnets []Vmnet `json:"vmnets"`
	}
	if err := r.do("GET", "/api/vmnet", nil, &res); err != nil {
		return nil, err
	}
	return res.Vmnets, nil
}

func (r *Rest) CreateVmnet(name, typ, subnet, mask string, dhcp bool) (*Vmnet, error) {
	body := map[string]string{"name": name, "type": typ, "subnet": subnet, "mask": mask}
	if dhcp {
		body["dhcp"] = "true"
	} else {
		body["dhcp"] = "false"
	}
	var out Vmnet
	if err := r.do("POST", "/api/vmnets", body, &out); err != nil {
		return nil, err
	}
	if out.Name == "" {
		out = Vmnet{Name: name, Type: typ, Subnet: subnet, Mask: mask, DHCP: body["dhcp"]}
	}
	return &out, nil
}
