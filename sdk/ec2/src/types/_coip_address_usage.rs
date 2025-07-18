// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes address usage for a customer-owned address pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CoipAddressUsage {
    /// <p>The allocation ID of the address.</p>
    pub allocation_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services service.</p>
    pub aws_service: ::std::option::Option<::std::string::String>,
    /// <p>The customer-owned IP address.</p>
    pub co_ip: ::std::option::Option<::std::string::String>,
}
impl CoipAddressUsage {
    /// <p>The allocation ID of the address.</p>
    pub fn allocation_id(&self) -> ::std::option::Option<&str> {
        self.allocation_id.as_deref()
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The Amazon Web Services service.</p>
    pub fn aws_service(&self) -> ::std::option::Option<&str> {
        self.aws_service.as_deref()
    }
    /// <p>The customer-owned IP address.</p>
    pub fn co_ip(&self) -> ::std::option::Option<&str> {
        self.co_ip.as_deref()
    }
}
impl CoipAddressUsage {
    /// Creates a new builder-style object to manufacture [`CoipAddressUsage`](crate::types::CoipAddressUsage).
    pub fn builder() -> crate::types::builders::CoipAddressUsageBuilder {
        crate::types::builders::CoipAddressUsageBuilder::default()
    }
}

/// A builder for [`CoipAddressUsage`](crate::types::CoipAddressUsage).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CoipAddressUsageBuilder {
    pub(crate) allocation_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_service: ::std::option::Option<::std::string::String>,
    pub(crate) co_ip: ::std::option::Option<::std::string::String>,
}
impl CoipAddressUsageBuilder {
    /// <p>The allocation ID of the address.</p>
    pub fn allocation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.allocation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The allocation ID of the address.</p>
    pub fn set_allocation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.allocation_id = input;
        self
    }
    /// <p>The allocation ID of the address.</p>
    pub fn get_allocation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.allocation_id
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The Amazon Web Services service.</p>
    pub fn aws_service(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_service = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services service.</p>
    pub fn set_aws_service(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_service = input;
        self
    }
    /// <p>The Amazon Web Services service.</p>
    pub fn get_aws_service(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_service
    }
    /// <p>The customer-owned IP address.</p>
    pub fn co_ip(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.co_ip = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The customer-owned IP address.</p>
    pub fn set_co_ip(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.co_ip = input;
        self
    }
    /// <p>The customer-owned IP address.</p>
    pub fn get_co_ip(&self) -> &::std::option::Option<::std::string::String> {
        &self.co_ip
    }
    /// Consumes the builder and constructs a [`CoipAddressUsage`](crate::types::CoipAddressUsage).
    pub fn build(self) -> crate::types::CoipAddressUsage {
        crate::types::CoipAddressUsage {
            allocation_id: self.allocation_id,
            aws_account_id: self.aws_account_id,
            aws_service: self.aws_service,
            co_ip: self.co_ip,
        }
    }
}
