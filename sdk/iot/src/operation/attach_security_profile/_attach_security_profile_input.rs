// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttachSecurityProfileInput {
    /// <p>The security profile that is attached.</p>
    pub security_profile_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the target (thing group) to which the security profile is attached.</p>
    pub security_profile_target_arn: ::std::option::Option<::std::string::String>,
}
impl AttachSecurityProfileInput {
    /// <p>The security profile that is attached.</p>
    pub fn security_profile_name(&self) -> ::std::option::Option<&str> {
        self.security_profile_name.as_deref()
    }
    /// <p>The ARN of the target (thing group) to which the security profile is attached.</p>
    pub fn security_profile_target_arn(&self) -> ::std::option::Option<&str> {
        self.security_profile_target_arn.as_deref()
    }
}
impl AttachSecurityProfileInput {
    /// Creates a new builder-style object to manufacture [`AttachSecurityProfileInput`](crate::operation::attach_security_profile::AttachSecurityProfileInput).
    pub fn builder() -> crate::operation::attach_security_profile::builders::AttachSecurityProfileInputBuilder {
        crate::operation::attach_security_profile::builders::AttachSecurityProfileInputBuilder::default()
    }
}

/// A builder for [`AttachSecurityProfileInput`](crate::operation::attach_security_profile::AttachSecurityProfileInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttachSecurityProfileInputBuilder {
    pub(crate) security_profile_name: ::std::option::Option<::std::string::String>,
    pub(crate) security_profile_target_arn: ::std::option::Option<::std::string::String>,
}
impl AttachSecurityProfileInputBuilder {
    /// <p>The security profile that is attached.</p>
    /// This field is required.
    pub fn security_profile_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_profile_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The security profile that is attached.</p>
    pub fn set_security_profile_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_profile_name = input;
        self
    }
    /// <p>The security profile that is attached.</p>
    pub fn get_security_profile_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_profile_name
    }
    /// <p>The ARN of the target (thing group) to which the security profile is attached.</p>
    /// This field is required.
    pub fn security_profile_target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_profile_target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the target (thing group) to which the security profile is attached.</p>
    pub fn set_security_profile_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_profile_target_arn = input;
        self
    }
    /// <p>The ARN of the target (thing group) to which the security profile is attached.</p>
    pub fn get_security_profile_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_profile_target_arn
    }
    /// Consumes the builder and constructs a [`AttachSecurityProfileInput`](crate::operation::attach_security_profile::AttachSecurityProfileInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::attach_security_profile::AttachSecurityProfileInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::attach_security_profile::AttachSecurityProfileInput {
            security_profile_name: self.security_profile_name,
            security_profile_target_arn: self.security_profile_target_arn,
        })
    }
}
