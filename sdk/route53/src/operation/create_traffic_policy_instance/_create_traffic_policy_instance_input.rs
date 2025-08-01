// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that contains information about the resource record sets that you want to create based on a specified traffic policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTrafficPolicyInstanceInput {
    /// <p>The ID of the hosted zone that you want Amazon Route 53 to create resource record sets in by using the configuration in a traffic policy.</p>
    pub hosted_zone_id: ::std::option::Option<::std::string::String>,
    /// <p>The domain name (such as example.com) or subdomain name (such as www.example.com) for which Amazon Route 53 responds to DNS queries by using the resource record sets that Route 53 creates for this traffic policy instance.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>(Optional) The TTL that you want Amazon Route 53 to assign to all of the resource record sets that it creates in the specified hosted zone.</p>
    pub ttl: ::std::option::Option<i64>,
    /// <p>The ID of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub traffic_policy_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub traffic_policy_version: ::std::option::Option<i32>,
}
impl CreateTrafficPolicyInstanceInput {
    /// <p>The ID of the hosted zone that you want Amazon Route 53 to create resource record sets in by using the configuration in a traffic policy.</p>
    pub fn hosted_zone_id(&self) -> ::std::option::Option<&str> {
        self.hosted_zone_id.as_deref()
    }
    /// <p>The domain name (such as example.com) or subdomain name (such as www.example.com) for which Amazon Route 53 responds to DNS queries by using the resource record sets that Route 53 creates for this traffic policy instance.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>(Optional) The TTL that you want Amazon Route 53 to assign to all of the resource record sets that it creates in the specified hosted zone.</p>
    pub fn ttl(&self) -> ::std::option::Option<i64> {
        self.ttl
    }
    /// <p>The ID of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn traffic_policy_id(&self) -> ::std::option::Option<&str> {
        self.traffic_policy_id.as_deref()
    }
    /// <p>The version of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn traffic_policy_version(&self) -> ::std::option::Option<i32> {
        self.traffic_policy_version
    }
}
impl CreateTrafficPolicyInstanceInput {
    /// Creates a new builder-style object to manufacture [`CreateTrafficPolicyInstanceInput`](crate::operation::create_traffic_policy_instance::CreateTrafficPolicyInstanceInput).
    pub fn builder() -> crate::operation::create_traffic_policy_instance::builders::CreateTrafficPolicyInstanceInputBuilder {
        crate::operation::create_traffic_policy_instance::builders::CreateTrafficPolicyInstanceInputBuilder::default()
    }
}

/// A builder for [`CreateTrafficPolicyInstanceInput`](crate::operation::create_traffic_policy_instance::CreateTrafficPolicyInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTrafficPolicyInstanceInputBuilder {
    pub(crate) hosted_zone_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) ttl: ::std::option::Option<i64>,
    pub(crate) traffic_policy_id: ::std::option::Option<::std::string::String>,
    pub(crate) traffic_policy_version: ::std::option::Option<i32>,
}
impl CreateTrafficPolicyInstanceInputBuilder {
    /// <p>The ID of the hosted zone that you want Amazon Route 53 to create resource record sets in by using the configuration in a traffic policy.</p>
    /// This field is required.
    pub fn hosted_zone_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hosted_zone_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the hosted zone that you want Amazon Route 53 to create resource record sets in by using the configuration in a traffic policy.</p>
    pub fn set_hosted_zone_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hosted_zone_id = input;
        self
    }
    /// <p>The ID of the hosted zone that you want Amazon Route 53 to create resource record sets in by using the configuration in a traffic policy.</p>
    pub fn get_hosted_zone_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hosted_zone_id
    }
    /// <p>The domain name (such as example.com) or subdomain name (such as www.example.com) for which Amazon Route 53 responds to DNS queries by using the resource record sets that Route 53 creates for this traffic policy instance.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name (such as example.com) or subdomain name (such as www.example.com) for which Amazon Route 53 responds to DNS queries by using the resource record sets that Route 53 creates for this traffic policy instance.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The domain name (such as example.com) or subdomain name (such as www.example.com) for which Amazon Route 53 responds to DNS queries by using the resource record sets that Route 53 creates for this traffic policy instance.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>(Optional) The TTL that you want Amazon Route 53 to assign to all of the resource record sets that it creates in the specified hosted zone.</p>
    /// This field is required.
    pub fn ttl(mut self, input: i64) -> Self {
        self.ttl = ::std::option::Option::Some(input);
        self
    }
    /// <p>(Optional) The TTL that you want Amazon Route 53 to assign to all of the resource record sets that it creates in the specified hosted zone.</p>
    pub fn set_ttl(mut self, input: ::std::option::Option<i64>) -> Self {
        self.ttl = input;
        self
    }
    /// <p>(Optional) The TTL that you want Amazon Route 53 to assign to all of the resource record sets that it creates in the specified hosted zone.</p>
    pub fn get_ttl(&self) -> &::std::option::Option<i64> {
        &self.ttl
    }
    /// <p>The ID of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    /// This field is required.
    pub fn traffic_policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.traffic_policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn set_traffic_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.traffic_policy_id = input;
        self
    }
    /// <p>The ID of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn get_traffic_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.traffic_policy_id
    }
    /// <p>The version of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    /// This field is required.
    pub fn traffic_policy_version(mut self, input: i32) -> Self {
        self.traffic_policy_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn set_traffic_policy_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.traffic_policy_version = input;
        self
    }
    /// <p>The version of the traffic policy that you want to use to create resource record sets in the specified hosted zone.</p>
    pub fn get_traffic_policy_version(&self) -> &::std::option::Option<i32> {
        &self.traffic_policy_version
    }
    /// Consumes the builder and constructs a [`CreateTrafficPolicyInstanceInput`](crate::operation::create_traffic_policy_instance::CreateTrafficPolicyInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_traffic_policy_instance::CreateTrafficPolicyInstanceInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_traffic_policy_instance::CreateTrafficPolicyInstanceInput {
            hosted_zone_id: self.hosted_zone_id,
            name: self.name,
            ttl: self.ttl,
            traffic_policy_id: self.traffic_policy_id,
            traffic_policy_version: self.traffic_policy_version,
        })
    }
}
