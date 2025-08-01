// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[deprecated(
    note = "AWS RoboMaker is unable to process this request as the support for the AWS RoboMaker application deployment feature has ended. For additional information, see https://docs.aws.amazon.com/robomaker/latest/dg/fleets.html."
)]
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRobotOutput {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the robot.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The time, in milliseconds since the epoch, when the robot was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) of the Greengrass group associated with the robot.</p>
    pub greengrass_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The target architecture of the robot.</p>
    pub architecture: ::std::option::Option<crate::types::Architecture>,
    /// <p>The list of all tags added to the robot.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateRobotOutput {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The name of the robot.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The time, in milliseconds since the epoch, when the robot was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Greengrass group associated with the robot.</p>
    pub fn greengrass_group_id(&self) -> ::std::option::Option<&str> {
        self.greengrass_group_id.as_deref()
    }
    /// <p>The target architecture of the robot.</p>
    pub fn architecture(&self) -> ::std::option::Option<&crate::types::Architecture> {
        self.architecture.as_ref()
    }
    /// <p>The list of all tags added to the robot.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRobotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRobotOutput {
    /// Creates a new builder-style object to manufacture [`CreateRobotOutput`](crate::operation::create_robot::CreateRobotOutput).
    pub fn builder() -> crate::operation::create_robot::builders::CreateRobotOutputBuilder {
        crate::operation::create_robot::builders::CreateRobotOutputBuilder::default()
    }
}

/// A builder for [`CreateRobotOutput`](crate::operation::create_robot::CreateRobotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRobotOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) greengrass_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) architecture: ::std::option::Option<crate::types::Architecture>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateRobotOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The name of the robot.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the robot.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the robot.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time, in milliseconds since the epoch, when the robot was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the robot was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the robot was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Amazon Resource Name (ARN) of the Greengrass group associated with the robot.</p>
    pub fn greengrass_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.greengrass_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Greengrass group associated with the robot.</p>
    pub fn set_greengrass_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.greengrass_group_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Greengrass group associated with the robot.</p>
    pub fn get_greengrass_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.greengrass_group_id
    }
    /// <p>The target architecture of the robot.</p>
    pub fn architecture(mut self, input: crate::types::Architecture) -> Self {
        self.architecture = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target architecture of the robot.</p>
    pub fn set_architecture(mut self, input: ::std::option::Option<crate::types::Architecture>) -> Self {
        self.architecture = input;
        self
    }
    /// <p>The target architecture of the robot.</p>
    pub fn get_architecture(&self) -> &::std::option::Option<crate::types::Architecture> {
        &self.architecture
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of all tags added to the robot.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The list of all tags added to the robot.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of all tags added to the robot.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateRobotOutput`](crate::operation::create_robot::CreateRobotOutput).
    pub fn build(self) -> crate::operation::create_robot::CreateRobotOutput {
        crate::operation::create_robot::CreateRobotOutput {
            arn: self.arn,
            name: self.name,
            created_at: self.created_at,
            greengrass_group_id: self.greengrass_group_id,
            architecture: self.architecture,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
