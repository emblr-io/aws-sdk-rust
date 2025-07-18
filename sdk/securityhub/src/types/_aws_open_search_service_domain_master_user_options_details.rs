// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies information about the master user of the domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsOpenSearchServiceDomainMasterUserOptionsDetails {
    /// <p>The Amazon Resource Name (ARN) for the master user.</p>
    pub master_user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The username for the master user.</p>
    pub master_user_name: ::std::option::Option<::std::string::String>,
    /// <p>The password for the master user.</p>
    pub master_user_password: ::std::option::Option<::std::string::String>,
}
impl AwsOpenSearchServiceDomainMasterUserOptionsDetails {
    /// <p>The Amazon Resource Name (ARN) for the master user.</p>
    pub fn master_user_arn(&self) -> ::std::option::Option<&str> {
        self.master_user_arn.as_deref()
    }
    /// <p>The username for the master user.</p>
    pub fn master_user_name(&self) -> ::std::option::Option<&str> {
        self.master_user_name.as_deref()
    }
    /// <p>The password for the master user.</p>
    pub fn master_user_password(&self) -> ::std::option::Option<&str> {
        self.master_user_password.as_deref()
    }
}
impl AwsOpenSearchServiceDomainMasterUserOptionsDetails {
    /// Creates a new builder-style object to manufacture [`AwsOpenSearchServiceDomainMasterUserOptionsDetails`](crate::types::AwsOpenSearchServiceDomainMasterUserOptionsDetails).
    pub fn builder() -> crate::types::builders::AwsOpenSearchServiceDomainMasterUserOptionsDetailsBuilder {
        crate::types::builders::AwsOpenSearchServiceDomainMasterUserOptionsDetailsBuilder::default()
    }
}

/// A builder for [`AwsOpenSearchServiceDomainMasterUserOptionsDetails`](crate::types::AwsOpenSearchServiceDomainMasterUserOptionsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsOpenSearchServiceDomainMasterUserOptionsDetailsBuilder {
    pub(crate) master_user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) master_user_name: ::std::option::Option<::std::string::String>,
    pub(crate) master_user_password: ::std::option::Option<::std::string::String>,
}
impl AwsOpenSearchServiceDomainMasterUserOptionsDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) for the master user.</p>
    pub fn master_user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the master user.</p>
    pub fn set_master_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the master user.</p>
    pub fn get_master_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_arn
    }
    /// <p>The username for the master user.</p>
    pub fn master_user_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The username for the master user.</p>
    pub fn set_master_user_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_name = input;
        self
    }
    /// <p>The username for the master user.</p>
    pub fn get_master_user_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_name
    }
    /// <p>The password for the master user.</p>
    pub fn master_user_password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.master_user_password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The password for the master user.</p>
    pub fn set_master_user_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.master_user_password = input;
        self
    }
    /// <p>The password for the master user.</p>
    pub fn get_master_user_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.master_user_password
    }
    /// Consumes the builder and constructs a [`AwsOpenSearchServiceDomainMasterUserOptionsDetails`](crate::types::AwsOpenSearchServiceDomainMasterUserOptionsDetails).
    pub fn build(self) -> crate::types::AwsOpenSearchServiceDomainMasterUserOptionsDetails {
        crate::types::AwsOpenSearchServiceDomainMasterUserOptionsDetails {
            master_user_arn: self.master_user_arn,
            master_user_name: self.master_user_name,
            master_user_password: self.master_user_password,
        }
    }
}
