// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[deprecated(
    note = "Support for the AWS RoboMaker application deployment feature has ended. For additional information, see https://docs.aws.amazon.com/robomaker/latest/dg/fleets.html."
)]
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRobotInput {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub robot: ::std::option::Option<::std::string::String>,
}
impl DeleteRobotInput {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn robot(&self) -> ::std::option::Option<&str> {
        self.robot.as_deref()
    }
}
impl DeleteRobotInput {
    /// Creates a new builder-style object to manufacture [`DeleteRobotInput`](crate::operation::delete_robot::DeleteRobotInput).
    pub fn builder() -> crate::operation::delete_robot::builders::DeleteRobotInputBuilder {
        crate::operation::delete_robot::builders::DeleteRobotInputBuilder::default()
    }
}

/// A builder for [`DeleteRobotInput`](crate::operation::delete_robot::DeleteRobotInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRobotInputBuilder {
    pub(crate) robot: ::std::option::Option<::std::string::String>,
}
impl DeleteRobotInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    /// This field is required.
    pub fn robot(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.robot = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn set_robot(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.robot = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn get_robot(&self) -> &::std::option::Option<::std::string::String> {
        &self.robot
    }
    /// Consumes the builder and constructs a [`DeleteRobotInput`](crate::operation::delete_robot::DeleteRobotInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_robot::DeleteRobotInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_robot::DeleteRobotInput { robot: self.robot })
    }
}
