// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRoutingProfileConcurrencyInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the routing profile.</p>
    pub routing_profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub media_concurrencies: ::std::option::Option<::std::vec::Vec<crate::types::MediaConcurrency>>,
}
impl UpdateRoutingProfileConcurrencyInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier of the routing profile.</p>
    pub fn routing_profile_id(&self) -> ::std::option::Option<&str> {
        self.routing_profile_id.as_deref()
    }
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.media_concurrencies.is_none()`.
    pub fn media_concurrencies(&self) -> &[crate::types::MediaConcurrency] {
        self.media_concurrencies.as_deref().unwrap_or_default()
    }
}
impl UpdateRoutingProfileConcurrencyInput {
    /// Creates a new builder-style object to manufacture [`UpdateRoutingProfileConcurrencyInput`](crate::operation::update_routing_profile_concurrency::UpdateRoutingProfileConcurrencyInput).
    pub fn builder() -> crate::operation::update_routing_profile_concurrency::builders::UpdateRoutingProfileConcurrencyInputBuilder {
        crate::operation::update_routing_profile_concurrency::builders::UpdateRoutingProfileConcurrencyInputBuilder::default()
    }
}

/// A builder for [`UpdateRoutingProfileConcurrencyInput`](crate::operation::update_routing_profile_concurrency::UpdateRoutingProfileConcurrencyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRoutingProfileConcurrencyInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) routing_profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) media_concurrencies: ::std::option::Option<::std::vec::Vec<crate::types::MediaConcurrency>>,
}
impl UpdateRoutingProfileConcurrencyInputBuilder {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier of the routing profile.</p>
    /// This field is required.
    pub fn routing_profile_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.routing_profile_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the routing profile.</p>
    pub fn set_routing_profile_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.routing_profile_id = input;
        self
    }
    /// <p>The identifier of the routing profile.</p>
    pub fn get_routing_profile_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.routing_profile_id
    }
    /// Appends an item to `media_concurrencies`.
    ///
    /// To override the contents of this collection use [`set_media_concurrencies`](Self::set_media_concurrencies).
    ///
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn media_concurrencies(mut self, input: crate::types::MediaConcurrency) -> Self {
        let mut v = self.media_concurrencies.unwrap_or_default();
        v.push(input);
        self.media_concurrencies = ::std::option::Option::Some(v);
        self
    }
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn set_media_concurrencies(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MediaConcurrency>>) -> Self {
        self.media_concurrencies = input;
        self
    }
    /// <p>The channels that agents can handle in the Contact Control Panel (CCP).</p>
    pub fn get_media_concurrencies(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MediaConcurrency>> {
        &self.media_concurrencies
    }
    /// Consumes the builder and constructs a [`UpdateRoutingProfileConcurrencyInput`](crate::operation::update_routing_profile_concurrency::UpdateRoutingProfileConcurrencyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_routing_profile_concurrency::UpdateRoutingProfileConcurrencyInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_routing_profile_concurrency::UpdateRoutingProfileConcurrencyInput {
                instance_id: self.instance_id,
                routing_profile_id: self.routing_profile_id,
                media_concurrencies: self.media_concurrencies,
            },
        )
    }
}
