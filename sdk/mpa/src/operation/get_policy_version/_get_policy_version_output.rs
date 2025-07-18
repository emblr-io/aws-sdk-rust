// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPolicyVersionOutput {
    /// <p>A <code>PolicyVersion</code> object. Contains details for the version of the policy. Policies define the permissions for team resources.</p>
    /// <p>The protected operation for a service integration might require specific permissions. For more information, see <a href="https://docs.aws.amazon.com/mpa/latest/userguide/mpa-integrations.html">How other services work with Multi-party approval</a> in the <i>Multi-party approval User Guide</i>.</p>
    pub policy_version: ::std::option::Option<crate::types::PolicyVersion>,
    _request_id: Option<String>,
}
impl GetPolicyVersionOutput {
    /// <p>A <code>PolicyVersion</code> object. Contains details for the version of the policy. Policies define the permissions for team resources.</p>
    /// <p>The protected operation for a service integration might require specific permissions. For more information, see <a href="https://docs.aws.amazon.com/mpa/latest/userguide/mpa-integrations.html">How other services work with Multi-party approval</a> in the <i>Multi-party approval User Guide</i>.</p>
    pub fn policy_version(&self) -> ::std::option::Option<&crate::types::PolicyVersion> {
        self.policy_version.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPolicyVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPolicyVersionOutput {
    /// Creates a new builder-style object to manufacture [`GetPolicyVersionOutput`](crate::operation::get_policy_version::GetPolicyVersionOutput).
    pub fn builder() -> crate::operation::get_policy_version::builders::GetPolicyVersionOutputBuilder {
        crate::operation::get_policy_version::builders::GetPolicyVersionOutputBuilder::default()
    }
}

/// A builder for [`GetPolicyVersionOutput`](crate::operation::get_policy_version::GetPolicyVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPolicyVersionOutputBuilder {
    pub(crate) policy_version: ::std::option::Option<crate::types::PolicyVersion>,
    _request_id: Option<String>,
}
impl GetPolicyVersionOutputBuilder {
    /// <p>A <code>PolicyVersion</code> object. Contains details for the version of the policy. Policies define the permissions for team resources.</p>
    /// <p>The protected operation for a service integration might require specific permissions. For more information, see <a href="https://docs.aws.amazon.com/mpa/latest/userguide/mpa-integrations.html">How other services work with Multi-party approval</a> in the <i>Multi-party approval User Guide</i>.</p>
    /// This field is required.
    pub fn policy_version(mut self, input: crate::types::PolicyVersion) -> Self {
        self.policy_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>PolicyVersion</code> object. Contains details for the version of the policy. Policies define the permissions for team resources.</p>
    /// <p>The protected operation for a service integration might require specific permissions. For more information, see <a href="https://docs.aws.amazon.com/mpa/latest/userguide/mpa-integrations.html">How other services work with Multi-party approval</a> in the <i>Multi-party approval User Guide</i>.</p>
    pub fn set_policy_version(mut self, input: ::std::option::Option<crate::types::PolicyVersion>) -> Self {
        self.policy_version = input;
        self
    }
    /// <p>A <code>PolicyVersion</code> object. Contains details for the version of the policy. Policies define the permissions for team resources.</p>
    /// <p>The protected operation for a service integration might require specific permissions. For more information, see <a href="https://docs.aws.amazon.com/mpa/latest/userguide/mpa-integrations.html">How other services work with Multi-party approval</a> in the <i>Multi-party approval User Guide</i>.</p>
    pub fn get_policy_version(&self) -> &::std::option::Option<crate::types::PolicyVersion> {
        &self.policy_version
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPolicyVersionOutput`](crate::operation::get_policy_version::GetPolicyVersionOutput).
    pub fn build(self) -> crate::operation::get_policy_version::GetPolicyVersionOutput {
        crate::operation::get_policy_version::GetPolicyVersionOutput {
            policy_version: self.policy_version,
            _request_id: self._request_id,
        }
    }
}
