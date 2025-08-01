// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRoutingProfileNameInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the routing profile.</p>
    pub routing_profile_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the routing profile. Must not be more than 127 characters.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the routing profile. Must not be more than 250 characters.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateRoutingProfileNameInput {
    /// <p>The identifier of the Amazon Connect instance. You can <a href="https://docs.aws.amazon.com/connect/latest/adminguide/find-instance-arn.html">find the instance ID</a> in the Amazon Resource Name (ARN) of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier of the routing profile.</p>
    pub fn routing_profile_id(&self) -> ::std::option::Option<&str> {
        self.routing_profile_id.as_deref()
    }
    /// <p>The name of the routing profile. Must not be more than 127 characters.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the routing profile. Must not be more than 250 characters.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateRoutingProfileNameInput {
    /// Creates a new builder-style object to manufacture [`UpdateRoutingProfileNameInput`](crate::operation::update_routing_profile_name::UpdateRoutingProfileNameInput).
    pub fn builder() -> crate::operation::update_routing_profile_name::builders::UpdateRoutingProfileNameInputBuilder {
        crate::operation::update_routing_profile_name::builders::UpdateRoutingProfileNameInputBuilder::default()
    }
}

/// A builder for [`UpdateRoutingProfileNameInput`](crate::operation::update_routing_profile_name::UpdateRoutingProfileNameInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRoutingProfileNameInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) routing_profile_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateRoutingProfileNameInputBuilder {
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
    /// <p>The name of the routing profile. Must not be more than 127 characters.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the routing profile. Must not be more than 127 characters.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the routing profile. Must not be more than 127 characters.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the routing profile. Must not be more than 250 characters.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the routing profile. Must not be more than 250 characters.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the routing profile. Must not be more than 250 characters.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateRoutingProfileNameInput`](crate::operation::update_routing_profile_name::UpdateRoutingProfileNameInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_routing_profile_name::UpdateRoutingProfileNameInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_routing_profile_name::UpdateRoutingProfileNameInput {
            instance_id: self.instance_id,
            routing_profile_id: self.routing_profile_id,
            name: self.name,
            description: self.description,
        })
    }
}
