// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutKeyPolicyInput {
    /// <p>Sets the key policy on the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid value is <code>default</code>.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    /// <p>The key policy to attach to the KMS key.</p>
    /// <p>The key policy must meet the following criteria:</p>
    /// <ul>
    /// <li>
    /// <p>The key policy must allow the calling principal to make a subsequent <code>PutKeyPolicy</code> request on the KMS key. This reduces the risk that the KMS key becomes unmanageable. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>. (To omit this condition, set <code>BypassPolicyLockoutSafetyCheck</code> to true.)</p></li>
    /// <li>
    /// <p>Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to KMS. When you create a new Amazon Web Services principal, you might need to enforce a delay before including the new principal in a key policy because the new principal might not be immediately visible to KMS. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency">Changes that I make are not always immediately visible</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p></li>
    /// </ul><note>
    /// <p>If either of the required <code>Resource</code> or <code>Action</code> elements are missing from a key policy statement, the policy statement has no effect. When a key policy statement is missing one of these elements, the KMS console correctly reports an error, but the <code>PutKeyPolicy</code> API request succeeds, even though the policy statement is ineffective.</p>
    /// <p>For more information on required key policy elements, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements">Elements in a key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </note>
    /// <p>A key policy document can include only the following characters:</p>
    /// <ul>
    /// <li>
    /// <p>Printable ASCII characters from the space character (<code>\u0020</code>) through the end of the ASCII character range.</p></li>
    /// <li>
    /// <p>Printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>).</p></li>
    /// <li>
    /// <p>The tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) special characters</p></li>
    /// </ul><note>
    /// <p>If the key policy exceeds the length constraint, KMS returns a <code>LimitExceededException</code>.</p>
    /// </note>
    /// <p>For information about key policies, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html">Key policies in KMS</a> in the <i>Key Management Service Developer Guide</i>.For help writing and formatting a JSON policy document, see the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html">IAM JSON Policy Reference</a> in the <i> <i>Identity and Access Management User Guide</i> </i>.</p>
    pub policy: ::std::option::Option<::std::string::String>,
    /// <p>Skips ("bypasses") the key policy lockout safety check. The default value is false.</p><important>
    /// <p>Setting this value to true increases the risk that the KMS key becomes unmanageable. Do not set this value to true indiscriminately.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </important>
    /// <p>Use this parameter only when you intend to prevent the principal that is making the request from making a subsequent <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html">PutKeyPolicy</a> request on the KMS key.</p>
    pub bypass_policy_lockout_safety_check: ::std::option::Option<bool>,
}
impl PutKeyPolicyInput {
    /// <p>Sets the key policy on the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>The name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid value is <code>default</code>.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
    /// <p>The key policy to attach to the KMS key.</p>
    /// <p>The key policy must meet the following criteria:</p>
    /// <ul>
    /// <li>
    /// <p>The key policy must allow the calling principal to make a subsequent <code>PutKeyPolicy</code> request on the KMS key. This reduces the risk that the KMS key becomes unmanageable. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>. (To omit this condition, set <code>BypassPolicyLockoutSafetyCheck</code> to true.)</p></li>
    /// <li>
    /// <p>Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to KMS. When you create a new Amazon Web Services principal, you might need to enforce a delay before including the new principal in a key policy because the new principal might not be immediately visible to KMS. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency">Changes that I make are not always immediately visible</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p></li>
    /// </ul><note>
    /// <p>If either of the required <code>Resource</code> or <code>Action</code> elements are missing from a key policy statement, the policy statement has no effect. When a key policy statement is missing one of these elements, the KMS console correctly reports an error, but the <code>PutKeyPolicy</code> API request succeeds, even though the policy statement is ineffective.</p>
    /// <p>For more information on required key policy elements, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements">Elements in a key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </note>
    /// <p>A key policy document can include only the following characters:</p>
    /// <ul>
    /// <li>
    /// <p>Printable ASCII characters from the space character (<code>\u0020</code>) through the end of the ASCII character range.</p></li>
    /// <li>
    /// <p>Printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>).</p></li>
    /// <li>
    /// <p>The tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) special characters</p></li>
    /// </ul><note>
    /// <p>If the key policy exceeds the length constraint, KMS returns a <code>LimitExceededException</code>.</p>
    /// </note>
    /// <p>For information about key policies, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html">Key policies in KMS</a> in the <i>Key Management Service Developer Guide</i>.For help writing and formatting a JSON policy document, see the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html">IAM JSON Policy Reference</a> in the <i> <i>Identity and Access Management User Guide</i> </i>.</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
    /// <p>Skips ("bypasses") the key policy lockout safety check. The default value is false.</p><important>
    /// <p>Setting this value to true increases the risk that the KMS key becomes unmanageable. Do not set this value to true indiscriminately.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </important>
    /// <p>Use this parameter only when you intend to prevent the principal that is making the request from making a subsequent <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html">PutKeyPolicy</a> request on the KMS key.</p>
    pub fn bypass_policy_lockout_safety_check(&self) -> ::std::option::Option<bool> {
        self.bypass_policy_lockout_safety_check
    }
}
impl PutKeyPolicyInput {
    /// Creates a new builder-style object to manufacture [`PutKeyPolicyInput`](crate::operation::put_key_policy::PutKeyPolicyInput).
    pub fn builder() -> crate::operation::put_key_policy::builders::PutKeyPolicyInputBuilder {
        crate::operation::put_key_policy::builders::PutKeyPolicyInputBuilder::default()
    }
}

/// A builder for [`PutKeyPolicyInput`](crate::operation::put_key_policy::PutKeyPolicyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutKeyPolicyInputBuilder {
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    pub(crate) bypass_policy_lockout_safety_check: ::std::option::Option<bool>,
}
impl PutKeyPolicyInputBuilder {
    /// <p>Sets the key policy on the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    /// This field is required.
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Sets the key policy on the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>Sets the key policy on the specified KMS key.</p>
    /// <p>Specify the key ID or key ARN of the KMS key.</p>
    /// <p>For example:</p>
    /// <ul>
    /// <li>
    /// <p>Key ID: <code>1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// <li>
    /// <p>Key ARN: <code>arn:aws:kms:us-east-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab</code></p></li>
    /// </ul>
    /// <p>To get the key ID and key ARN for a KMS key, use <code>ListKeys</code> or <code>DescribeKey</code>.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// <p>The name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid value is <code>default</code>.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid value is <code>default</code>.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the key policy. If no policy name is specified, the default value is <code>default</code>. The only valid value is <code>default</code>.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    /// <p>The key policy to attach to the KMS key.</p>
    /// <p>The key policy must meet the following criteria:</p>
    /// <ul>
    /// <li>
    /// <p>The key policy must allow the calling principal to make a subsequent <code>PutKeyPolicy</code> request on the KMS key. This reduces the risk that the KMS key becomes unmanageable. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>. (To omit this condition, set <code>BypassPolicyLockoutSafetyCheck</code> to true.)</p></li>
    /// <li>
    /// <p>Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to KMS. When you create a new Amazon Web Services principal, you might need to enforce a delay before including the new principal in a key policy because the new principal might not be immediately visible to KMS. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency">Changes that I make are not always immediately visible</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p></li>
    /// </ul><note>
    /// <p>If either of the required <code>Resource</code> or <code>Action</code> elements are missing from a key policy statement, the policy statement has no effect. When a key policy statement is missing one of these elements, the KMS console correctly reports an error, but the <code>PutKeyPolicy</code> API request succeeds, even though the policy statement is ineffective.</p>
    /// <p>For more information on required key policy elements, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements">Elements in a key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </note>
    /// <p>A key policy document can include only the following characters:</p>
    /// <ul>
    /// <li>
    /// <p>Printable ASCII characters from the space character (<code>\u0020</code>) through the end of the ASCII character range.</p></li>
    /// <li>
    /// <p>Printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>).</p></li>
    /// <li>
    /// <p>The tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) special characters</p></li>
    /// </ul><note>
    /// <p>If the key policy exceeds the length constraint, KMS returns a <code>LimitExceededException</code>.</p>
    /// </note>
    /// <p>For information about key policies, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html">Key policies in KMS</a> in the <i>Key Management Service Developer Guide</i>.For help writing and formatting a JSON policy document, see the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html">IAM JSON Policy Reference</a> in the <i> <i>Identity and Access Management User Guide</i> </i>.</p>
    /// This field is required.
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key policy to attach to the KMS key.</p>
    /// <p>The key policy must meet the following criteria:</p>
    /// <ul>
    /// <li>
    /// <p>The key policy must allow the calling principal to make a subsequent <code>PutKeyPolicy</code> request on the KMS key. This reduces the risk that the KMS key becomes unmanageable. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>. (To omit this condition, set <code>BypassPolicyLockoutSafetyCheck</code> to true.)</p></li>
    /// <li>
    /// <p>Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to KMS. When you create a new Amazon Web Services principal, you might need to enforce a delay before including the new principal in a key policy because the new principal might not be immediately visible to KMS. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency">Changes that I make are not always immediately visible</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p></li>
    /// </ul><note>
    /// <p>If either of the required <code>Resource</code> or <code>Action</code> elements are missing from a key policy statement, the policy statement has no effect. When a key policy statement is missing one of these elements, the KMS console correctly reports an error, but the <code>PutKeyPolicy</code> API request succeeds, even though the policy statement is ineffective.</p>
    /// <p>For more information on required key policy elements, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements">Elements in a key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </note>
    /// <p>A key policy document can include only the following characters:</p>
    /// <ul>
    /// <li>
    /// <p>Printable ASCII characters from the space character (<code>\u0020</code>) through the end of the ASCII character range.</p></li>
    /// <li>
    /// <p>Printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>).</p></li>
    /// <li>
    /// <p>The tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) special characters</p></li>
    /// </ul><note>
    /// <p>If the key policy exceeds the length constraint, KMS returns a <code>LimitExceededException</code>.</p>
    /// </note>
    /// <p>For information about key policies, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html">Key policies in KMS</a> in the <i>Key Management Service Developer Guide</i>.For help writing and formatting a JSON policy document, see the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html">IAM JSON Policy Reference</a> in the <i> <i>Identity and Access Management User Guide</i> </i>.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>The key policy to attach to the KMS key.</p>
    /// <p>The key policy must meet the following criteria:</p>
    /// <ul>
    /// <li>
    /// <p>The key policy must allow the calling principal to make a subsequent <code>PutKeyPolicy</code> request on the KMS key. This reduces the risk that the KMS key becomes unmanageable. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>. (To omit this condition, set <code>BypassPolicyLockoutSafetyCheck</code> to true.)</p></li>
    /// <li>
    /// <p>Each statement in the key policy must contain one or more principals. The principals in the key policy must exist and be visible to KMS. When you create a new Amazon Web Services principal, you might need to enforce a delay before including the new principal in a key policy because the new principal might not be immediately visible to KMS. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency">Changes that I make are not always immediately visible</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p></li>
    /// </ul><note>
    /// <p>If either of the required <code>Resource</code> or <code>Action</code> elements are missing from a key policy statement, the policy statement has no effect. When a key policy statement is missing one of these elements, the KMS console correctly reports an error, but the <code>PutKeyPolicy</code> API request succeeds, even though the policy statement is ineffective.</p>
    /// <p>For more information on required key policy elements, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-overview.html#key-policy-elements">Elements in a key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </note>
    /// <p>A key policy document can include only the following characters:</p>
    /// <ul>
    /// <li>
    /// <p>Printable ASCII characters from the space character (<code>\u0020</code>) through the end of the ASCII character range.</p></li>
    /// <li>
    /// <p>Printable characters in the Basic Latin and Latin-1 Supplement character set (through <code>\u00FF</code>).</p></li>
    /// <li>
    /// <p>The tab (<code>\u0009</code>), line feed (<code>\u000A</code>), and carriage return (<code>\u000D</code>) special characters</p></li>
    /// </ul><note>
    /// <p>If the key policy exceeds the length constraint, KMS returns a <code>LimitExceededException</code>.</p>
    /// </note>
    /// <p>For information about key policies, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html">Key policies in KMS</a> in the <i>Key Management Service Developer Guide</i>.For help writing and formatting a JSON policy document, see the <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies.html">IAM JSON Policy Reference</a> in the <i> <i>Identity and Access Management User Guide</i> </i>.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// <p>Skips ("bypasses") the key policy lockout safety check. The default value is false.</p><important>
    /// <p>Setting this value to true increases the risk that the KMS key becomes unmanageable. Do not set this value to true indiscriminately.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </important>
    /// <p>Use this parameter only when you intend to prevent the principal that is making the request from making a subsequent <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html">PutKeyPolicy</a> request on the KMS key.</p>
    pub fn bypass_policy_lockout_safety_check(mut self, input: bool) -> Self {
        self.bypass_policy_lockout_safety_check = ::std::option::Option::Some(input);
        self
    }
    /// <p>Skips ("bypasses") the key policy lockout safety check. The default value is false.</p><important>
    /// <p>Setting this value to true increases the risk that the KMS key becomes unmanageable. Do not set this value to true indiscriminately.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </important>
    /// <p>Use this parameter only when you intend to prevent the principal that is making the request from making a subsequent <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html">PutKeyPolicy</a> request on the KMS key.</p>
    pub fn set_bypass_policy_lockout_safety_check(mut self, input: ::std::option::Option<bool>) -> Self {
        self.bypass_policy_lockout_safety_check = input;
        self
    }
    /// <p>Skips ("bypasses") the key policy lockout safety check. The default value is false.</p><important>
    /// <p>Setting this value to true increases the risk that the KMS key becomes unmanageable. Do not set this value to true indiscriminately.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html#prevent-unmanageable-key">Default key policy</a> in the <i>Key Management Service Developer Guide</i>.</p>
    /// </important>
    /// <p>Use this parameter only when you intend to prevent the principal that is making the request from making a subsequent <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_PutKeyPolicy.html">PutKeyPolicy</a> request on the KMS key.</p>
    pub fn get_bypass_policy_lockout_safety_check(&self) -> &::std::option::Option<bool> {
        &self.bypass_policy_lockout_safety_check
    }
    /// Consumes the builder and constructs a [`PutKeyPolicyInput`](crate::operation::put_key_policy::PutKeyPolicyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::put_key_policy::PutKeyPolicyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::put_key_policy::PutKeyPolicyInput {
            key_id: self.key_id,
            policy_name: self.policy_name,
            policy: self.policy,
            bypass_policy_lockout_safety_check: self.bypass_policy_lockout_safety_check,
        })
    }
}
