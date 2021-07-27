package rediswatcher

import (
	"encoding/json"
	"log"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
)

//go:generate mockgen -destination=mocks/mock_adapter.go -package=mocks github.com/casbin/casbin/v2/persist BatchAdapter,UpdatableAdapter

type SyncCallbackFunc func(msg string, update, updateForAddPolicy, updateForRemovePolicy, updateForRemoveFilteredPolicy,
	updateForSavePolicy, updateForAddPolicies, updateForRemovePolicies, updateForUpdatePolicy, updateForUpdatePolicies func(string, string, string, interface{}))

func SyncCustomDefaultFunc(defaultFunc func(string, string, string, interface{})) SyncCallbackFunc {
	return func(msg string, update, updateForAddPolicy, updateForRemovePolicy, updateForRemoveFilteredPolicy, updateForSavePolicy, updateForAddPolicies, updateForRemovePolicies, updateForUpdatePolicy, updateForUpdatePolicies func(string, string, string, interface{})) {
		msgStruct := &MSG{}
		err := msgStruct.UnmarshalBinary([]byte(msg))
		if err != nil {
			log.Println(err)
		}
		invoke := func(f func(string, string, string, interface{})) {
			if f == nil {
				f = defaultFunc
			}
			f(msgStruct.ID, msgStruct.Sec, msgStruct.Ptype, msgStruct.Params)
		}
		switch msgStruct.Method {
		case "Update":
			invoke(update)
		case "UpdateForAddPolicy":
			invoke(updateForAddPolicy)
		case "UpdateForRemovePolicy":
			invoke(updateForRemovePolicy)
		case "UpdateForRemoveFilteredPolicy":
			invoke(updateForRemoveFilteredPolicy)
		case "UpdateForSavePolicy":
			invoke(updateForSavePolicy)
		case "UpdateForAddPolicies":
			invoke(updateForAddPolicies)
		case "UpdateForRemovePolicies":
			invoke(updateForRemovePolicies)
		case "UpdateForUpdatePolicy":
			invoke(updateForUpdatePolicy)
		case "UpdateForUpdatePolicies":
			invoke(updateForUpdatePolicies)
		}
	}
}

type SyncedCallbackHandler struct {
	id     string
	e      *casbin.SyncedEnforcer
	logger Logger
}

// NewSyncedCallbackHandler constructor
func NewSyncedCallbackHandler(id string, e *casbin.SyncedEnforcer, logger Logger) *SyncedCallbackHandler {
	if logger == nil {
		logger = nil
	}
	c := &SyncedCallbackHandler{id: id, e: e, logger: logger}
	return c
}

func (c *SyncedCallbackHandler) ID() string {
	return c.id
}

func (c *SyncedCallbackHandler) Handle(data string) {
	SyncCustomDefaultFunc(
		func(id, sec, ptype string, params interface{}) {
			c.logger.Printf(nil, "method mapping error")
		},
	)(data, c.Update, c.UpdateForAddPolicy, c.UpdateForRemovePolicy, c.UpdateForRemoveFilteredPolicy, c.UpdateForSavePolicy, c.UpdateForAddPolicies, c.UpdateForRemovePolicies, c.UpdateForUpdatePolicy, c.UpdateForUpdatePolicies)
}

func (c *SyncedCallbackHandler) Update(id, sec, ptype string, params interface{}) {
	if c.id != id {
		c.e.LoadPolicy()
	}
}

func (c *SyncedCallbackHandler) UpdateForAddPolicy(id, sec, ptype string, params interface{}) {
	if c.id != id {
		policy := make([]string, 0)
		for _, v := range params.([]interface{}) {
			policy = append(policy, v.(string))
		}
		_ = c.e.GetOperator().AddPolicy(sec, ptype, policy)
	}
}

func (c *SyncedCallbackHandler) UpdateForRemovePolicy(id, sec, ptype string, params interface{}) {
	if c.id != id {
		policy := make([]string, 0)
		for _, v := range params.([]interface{}) {
			policy = append(policy, v.(string))
		}
		_, _ = c.e.GetOperator().RemovePolicy(sec, ptype, policy)
	}
}

func (c *SyncedCallbackHandler) UpdateForRemoveFilteredPolicy(id, sec, ptype string, params interface{}) {
	if c.id != id {
		paramstr := params.(string)
		paramstrtokens := strings.Split(paramstr, " ")
		fieldIndex, _ := strconv.Atoi(paramstrtokens[0])
		fieldValues := paramstrtokens[1:]
		_, _ = c.e.GetOperator().RemoveFilteredPolicy(sec, ptype, fieldIndex, fieldValues...)
	}
}

func (c *SyncedCallbackHandler) UpdateForSavePolicy(id, sec, ptype string, params interface{}) {
	if c.id != id {
		bytes, _ := json.Marshal(params)
		model := model.Model{}
		_ = json.Unmarshal(bytes, &model)
		model.PrintModel()
	}
}

func (c *SyncedCallbackHandler) UpdateForAddPolicies(id, sec, ptype string, params interface{}) {
	if c.id != id {
		policy := make([][]string, 0)
		for _, v := range params.([]interface{}) {
			rules := make([]string, 0)
			for _, v := range v.([]interface{}) {
				rules = append(rules, v.(string))
			}
			policy = append(policy, rules)
		}
		_ = c.e.GetOperator().AddPolicies(sec, ptype, policy)
	}
}

func (c *SyncedCallbackHandler) UpdateForRemovePolicies(id, sec, ptype string, params interface{}) {
	if c.id != id {
		policy := make([][]string, 0)
		for _, v := range params.([]interface{}) {
			rules := make([]string, 0)
			for _, v := range v.([]interface{}) {
				rules = append(rules, v.(string))
			}
			policy = append(policy, rules)
		}
		_, _ = c.e.GetOperator().RemovePolicies(sec, ptype, policy)
	}
}

func (c *SyncedCallbackHandler) UpdateForUpdatePolicy(id, sec, ptype string, params interface{}) {
	if c.id != id {
		updates, _ := params.(map[string]interface{})
		oldRule := make([]string, 0)
		for _, v := range (updates["OldRule"]).(interface{}).([]interface{}) {
			oldRule = append(oldRule, v.(string))
		}
		newRule := make([]string, 0)
		for _, v := range (updates["NewRule"]).(interface{}).([]interface{}) {
			newRule = append(newRule, v.(string))
		}
		_, _ = c.e.GetOperator().UpdatePolicy(sec, ptype, oldRule, newRule)
	}
}

func (c *SyncedCallbackHandler) UpdateForUpdatePolicies(id, sec, ptype string, params interface{}) {
	if c.id != id {
		updates, _ := params.(map[string]interface{})
		oldRule := make([][]string, 0)
		for _, v := range (updates["OldRule"]).(interface{}).([]interface{}) {
			rules := make([]string, 0)
			for _, v := range v.([]interface{}) {
				rules = append(rules, v.(string))
			}
			oldRule = append(oldRule, rules)
		}
		newRule := make([][]string, 0)
		for _, v := range (updates["NewRule"]).(interface{}).([]interface{}) {
			rules := make([]string, 0)
			for _, v := range v.([]interface{}) {
				rules = append(rules, v.(string))
			}
			newRule = append(newRule, rules)
		}
		_, _ = c.e.GetOperator().UpdatePolicies(sec, ptype, oldRule, newRule)
	}
}
