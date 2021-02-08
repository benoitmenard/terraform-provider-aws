package aws

import (
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go/aws"
	//"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	//"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceAwsIamPolicyAttachments() *schema.Resource {
	return &schema.Resource{
		Create: resourceAwsIamPolicyAttachmentsCreate,
		Read:   resourceAwsIamPolicyAttachmentsRead,
		Update: resourceAwsIamPolicyAttachmentsUpdate,
		Delete: resourceAwsIamPolicyAttachmentsDelete,

		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
			},
			"policy_arns": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
				Set:      schema.HashString,
			},
		},
	}
}

func resourceAwsIamPolicyAttachmentsCreate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).iamconn

	name := d.Get("name").(string)
	resourceType := d.Get("type").(string)
	policy_arns := expandStringSet(d.Get("policy_arns").(*schema.Set))

	var attachmentErr error
	for _, arn := range policy_arns {
		log.Printf("[TRACE] Managing the policy %s", arn)
		if resourceType == "role" {
			attachmentErr = attachPolicyToRole(conn, name, *arn)
		}
		if resourceType == "user" {
			attachmentErr = attachPolicyToUser(conn, name, *arn)
		}
		if resourceType == "group" {
			attachmentErr = attachPolicyToGroup(conn, name, *arn)
		}
		if attachmentErr != nil {
			return fmt.Errorf("Unable to attach the policy %s to %s/%s: %s", *arn, resourceType, name, attachmentErr)
		}
	}

	d.SetId(fmt.Sprintf("%s/%s", resourceType, name))
	return resourceAwsIamPolicyAttachmentsRead(d, meta)
}

func resourceAwsIamPolicyAttachmentsRead(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).iamconn

	name := d.Get("name").(string)
	resourceType := d.Get("type").(string)
	//var err error
	currentAttachedPolicies := make([]string, 0)
	var err error
	var userAttachedPolicies *iam.ListAttachedUserPoliciesOutput
	var roleAttachedPolicies *iam.ListAttachedRolePoliciesOutput
	var groupAttachedPolicies *iam.ListAttachedGroupPoliciesOutput
	if resourceType == "role" {
		roleAttachedPolicies, err = conn.ListAttachedRolePolicies(&iam.ListAttachedRolePoliciesInput{
			RoleName: aws.String(name),
		})
		for _, p := range roleAttachedPolicies.AttachedPolicies {
			currentAttachedPolicies = append(currentAttachedPolicies, *p.PolicyArn)
		}
	} else if resourceType == "user" {
		userAttachedPolicies, err = conn.ListAttachedUserPolicies(&iam.ListAttachedUserPoliciesInput{
			UserName: aws.String(name),
		})
		for _, p := range userAttachedPolicies.AttachedPolicies {
			currentAttachedPolicies = append(currentAttachedPolicies, *p.PolicyArn)
		}
	} else if resourceType == "group" {
		groupAttachedPolicies, err = conn.ListAttachedGroupPolicies(&iam.ListAttachedGroupPoliciesInput{
			GroupName: aws.String(name),
		})
		for _, p := range groupAttachedPolicies.AttachedPolicies {
			currentAttachedPolicies = append(currentAttachedPolicies, *p.PolicyArn)
		}
	}

	if err != nil {
		return fmt.Errorf("Error while listing attached policies for %s/%s: %s", resourceType, name, err)
	}

	d.Set("policy_arns", currentAttachedPolicies)

	return nil
}

func resourceAwsIamPolicyAttachmentsUpdate(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).iamconn
	name := d.Get("name").(string)
	resourceType := d.Get("type").(string)

	if d.HasChange("policy_arns") {
		var addErr, removeErr error
		o, n := d.GetChange("policy_arns")
		if o == nil {
			o = new(schema.Set)
		}
		if n == nil {
			n = new(schema.Set)
		}
		os := o.(*schema.Set)
		ns := n.(*schema.Set)
		remove := expandStringSet(os.Difference(ns))
		add := expandStringSet(ns.Difference(os))
	
		for _, p := range remove {
			removeErr = dettachPolicyFrom(conn, resourceType, name, *p)
			if removeErr != nil {
				return fmt.Errorf("Error while dettaching policy %s from  %s/%s: %s", *p, resourceType, name, removeErr)
			}
		}

		for _, p := range add {
			addErr = attachPolicyTo(conn, resourceType, name, *p)
			if addErr != nil {
				return fmt.Errorf("Error while attaching policy %s from  %s/%s: %s", *p, resourceType, name, addErr)
			}		
		}
	}

	return resourceAwsIamPolicyAttachmentsRead(d, meta)
}

func resourceAwsIamPolicyAttachmentsDelete(d *schema.ResourceData, meta interface{}) error {
	conn := meta.(*AWSClient).iamconn
	name := d.Get("name").(string)
	resourceType := d.Get("type").(string)
	policy_arns := expandStringSet(d.Get("policy_arns").(*schema.Set))

	var dettachErr error
	for _, p := range policy_arns {
		dettachErr = dettachPolicyFrom(conn, resourceType, name, *p)
		if dettachErr != nil {
			return fmt.Errorf("Error while dettaching policy %s from  %s/%s: %s", *p, resourceType, name, dettachErr)
		}
	}
	return nil
}

func attachPolicyTo(conn *iam.IAM, resourceType string, name string, arn string) error {
	var attachErr error
	if resourceType == "role" {
		attachErr = attachPolicyToRole(conn, name, arn)
	}
	if resourceType == "user" {
		attachErr = attachPolicyToUser(conn, name, arn)
	}
	if resourceType == "group" {
		attachErr = attachPolicyToGroup(conn, name, arn)
	}

	return attachErr
}

func dettachPolicyFrom(conn *iam.IAM, resourceType string, name string, arn string) error {
	var dettachErr error
	if resourceType == "role" {
		dettachErr = detachPolicyFromRole(conn, name, arn)
	}
	if resourceType == "user" {
		dettachErr = detachPolicyFromUser(conn, name, arn)
	}
	if resourceType == "group" {
		dettachErr = detachPolicyFromGroup(conn, name, arn)
	}
	return dettachErr
}
