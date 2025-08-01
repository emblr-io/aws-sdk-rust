// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AllocateHostedConnectionInput {
    /// <p>The ID of the interconnect or LAG.</p>
    pub connection_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Amazon Web Services account ID of the customer for the connection.</p>
    pub owner_account: ::std::option::Option<::std::string::String>,
    /// <p>The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, 10Gbps, and 25Gbps. Note that only those Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps, 10Gbps, or 25Gbps hosted connection.</p>
    pub bandwidth: ::std::option::Option<::std::string::String>,
    /// <p>The name of the hosted connection.</p>
    pub connection_name: ::std::option::Option<::std::string::String>,
    /// <p>The dedicated VLAN provisioned to the hosted connection.</p>
    pub vlan: ::std::option::Option<i32>,
    /// <p>The tags associated with the connection.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AllocateHostedConnectionInput {
    /// <p>The ID of the interconnect or LAG.</p>
    pub fn connection_id(&self) -> ::std::option::Option<&str> {
        self.connection_id.as_deref()
    }
    /// <p>The ID of the Amazon Web Services account ID of the customer for the connection.</p>
    pub fn owner_account(&self) -> ::std::option::Option<&str> {
        self.owner_account.as_deref()
    }
    /// <p>The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, 10Gbps, and 25Gbps. Note that only those Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps, 10Gbps, or 25Gbps hosted connection.</p>
    pub fn bandwidth(&self) -> ::std::option::Option<&str> {
        self.bandwidth.as_deref()
    }
    /// <p>The name of the hosted connection.</p>
    pub fn connection_name(&self) -> ::std::option::Option<&str> {
        self.connection_name.as_deref()
    }
    /// <p>The dedicated VLAN provisioned to the hosted connection.</p>
    pub fn vlan(&self) -> ::std::option::Option<i32> {
        self.vlan
    }
    /// <p>The tags associated with the connection.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl AllocateHostedConnectionInput {
    /// Creates a new builder-style object to manufacture [`AllocateHostedConnectionInput`](crate::operation::allocate_hosted_connection::AllocateHostedConnectionInput).
    pub fn builder() -> crate::operation::allocate_hosted_connection::builders::AllocateHostedConnectionInputBuilder {
        crate::operation::allocate_hosted_connection::builders::AllocateHostedConnectionInputBuilder::default()
    }
}

/// A builder for [`AllocateHostedConnectionInput`](crate::operation::allocate_hosted_connection::AllocateHostedConnectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AllocateHostedConnectionInputBuilder {
    pub(crate) connection_id: ::std::option::Option<::std::string::String>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) bandwidth: ::std::option::Option<::std::string::String>,
    pub(crate) connection_name: ::std::option::Option<::std::string::String>,
    pub(crate) vlan: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AllocateHostedConnectionInputBuilder {
    /// <p>The ID of the interconnect or LAG.</p>
    /// This field is required.
    pub fn connection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the interconnect or LAG.</p>
    pub fn set_connection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_id = input;
        self
    }
    /// <p>The ID of the interconnect or LAG.</p>
    pub fn get_connection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_id
    }
    /// <p>The ID of the Amazon Web Services account ID of the customer for the connection.</p>
    /// This field is required.
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Amazon Web Services account ID of the customer for the connection.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The ID of the Amazon Web Services account ID of the customer for the connection.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// <p>The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, 10Gbps, and 25Gbps. Note that only those Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps, 10Gbps, or 25Gbps hosted connection.</p>
    /// This field is required.
    pub fn bandwidth(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bandwidth = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, 10Gbps, and 25Gbps. Note that only those Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps, 10Gbps, or 25Gbps hosted connection.</p>
    pub fn set_bandwidth(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bandwidth = input;
        self
    }
    /// <p>The bandwidth of the connection. The possible values are 50Mbps, 100Mbps, 200Mbps, 300Mbps, 400Mbps, 500Mbps, 1Gbps, 2Gbps, 5Gbps, 10Gbps, and 25Gbps. Note that only those Direct Connect Partners who have met specific requirements are allowed to create a 1Gbps, 2Gbps, 5Gbps, 10Gbps, or 25Gbps hosted connection.</p>
    pub fn get_bandwidth(&self) -> &::std::option::Option<::std::string::String> {
        &self.bandwidth
    }
    /// <p>The name of the hosted connection.</p>
    /// This field is required.
    pub fn connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the hosted connection.</p>
    pub fn set_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_name = input;
        self
    }
    /// <p>The name of the hosted connection.</p>
    pub fn get_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_name
    }
    /// <p>The dedicated VLAN provisioned to the hosted connection.</p>
    /// This field is required.
    pub fn vlan(mut self, input: i32) -> Self {
        self.vlan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dedicated VLAN provisioned to the hosted connection.</p>
    pub fn set_vlan(mut self, input: ::std::option::Option<i32>) -> Self {
        self.vlan = input;
        self
    }
    /// <p>The dedicated VLAN provisioned to the hosted connection.</p>
    pub fn get_vlan(&self) -> &::std::option::Option<i32> {
        &self.vlan
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags associated with the connection.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags associated with the connection.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags associated with the connection.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`AllocateHostedConnectionInput`](crate::operation::allocate_hosted_connection::AllocateHostedConnectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::allocate_hosted_connection::AllocateHostedConnectionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::allocate_hosted_connection::AllocateHostedConnectionInput {
            connection_id: self.connection_id,
            owner_account: self.owner_account,
            bandwidth: self.bandwidth,
            connection_name: self.connection_name,
            vlan: self.vlan,
            tags: self.tags,
        })
    }
}
