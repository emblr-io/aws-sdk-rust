// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopApplicationInput {
    /// <p>The ID of the application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>Specify the <code>ConnectedEntityType</code>. Accepted type is <code>DBMS</code>.</p>
    /// <p>If this parameter is included, the connected DBMS (Database Management System) will be stopped.</p>
    pub stop_connected_entity: ::std::option::Option<crate::types::ConnectedEntityType>,
    /// <p>Boolean. If included and if set to <code>True</code>, the StopApplication operation will shut down the associated Amazon EC2 instance in addition to the application.</p>
    pub include_ec2_instance_shutdown: ::std::option::Option<bool>,
}
impl StopApplicationInput {
    /// <p>The ID of the application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>Specify the <code>ConnectedEntityType</code>. Accepted type is <code>DBMS</code>.</p>
    /// <p>If this parameter is included, the connected DBMS (Database Management System) will be stopped.</p>
    pub fn stop_connected_entity(&self) -> ::std::option::Option<&crate::types::ConnectedEntityType> {
        self.stop_connected_entity.as_ref()
    }
    /// <p>Boolean. If included and if set to <code>True</code>, the StopApplication operation will shut down the associated Amazon EC2 instance in addition to the application.</p>
    pub fn include_ec2_instance_shutdown(&self) -> ::std::option::Option<bool> {
        self.include_ec2_instance_shutdown
    }
}
impl StopApplicationInput {
    /// Creates a new builder-style object to manufacture [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
    pub fn builder() -> crate::operation::stop_application::builders::StopApplicationInputBuilder {
        crate::operation::stop_application::builders::StopApplicationInputBuilder::default()
    }
}

/// A builder for [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopApplicationInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) stop_connected_entity: ::std::option::Option<crate::types::ConnectedEntityType>,
    pub(crate) include_ec2_instance_shutdown: ::std::option::Option<bool>,
}
impl StopApplicationInputBuilder {
    /// <p>The ID of the application.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The ID of the application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>Specify the <code>ConnectedEntityType</code>. Accepted type is <code>DBMS</code>.</p>
    /// <p>If this parameter is included, the connected DBMS (Database Management System) will be stopped.</p>
    pub fn stop_connected_entity(mut self, input: crate::types::ConnectedEntityType) -> Self {
        self.stop_connected_entity = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify the <code>ConnectedEntityType</code>. Accepted type is <code>DBMS</code>.</p>
    /// <p>If this parameter is included, the connected DBMS (Database Management System) will be stopped.</p>
    pub fn set_stop_connected_entity(mut self, input: ::std::option::Option<crate::types::ConnectedEntityType>) -> Self {
        self.stop_connected_entity = input;
        self
    }
    /// <p>Specify the <code>ConnectedEntityType</code>. Accepted type is <code>DBMS</code>.</p>
    /// <p>If this parameter is included, the connected DBMS (Database Management System) will be stopped.</p>
    pub fn get_stop_connected_entity(&self) -> &::std::option::Option<crate::types::ConnectedEntityType> {
        &self.stop_connected_entity
    }
    /// <p>Boolean. If included and if set to <code>True</code>, the StopApplication operation will shut down the associated Amazon EC2 instance in addition to the application.</p>
    pub fn include_ec2_instance_shutdown(mut self, input: bool) -> Self {
        self.include_ec2_instance_shutdown = ::std::option::Option::Some(input);
        self
    }
    /// <p>Boolean. If included and if set to <code>True</code>, the StopApplication operation will shut down the associated Amazon EC2 instance in addition to the application.</p>
    pub fn set_include_ec2_instance_shutdown(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_ec2_instance_shutdown = input;
        self
    }
    /// <p>Boolean. If included and if set to <code>True</code>, the StopApplication operation will shut down the associated Amazon EC2 instance in addition to the application.</p>
    pub fn get_include_ec2_instance_shutdown(&self) -> &::std::option::Option<bool> {
        &self.include_ec2_instance_shutdown
    }
    /// Consumes the builder and constructs a [`StopApplicationInput`](crate::operation::stop_application::StopApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_application::StopApplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::stop_application::StopApplicationInput {
            application_id: self.application_id,
            stop_connected_entity: self.stop_connected_entity,
            include_ec2_instance_shutdown: self.include_ec2_instance_shutdown,
        })
    }
}
