// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[deprecated(
    note = "Support for the AWS RoboMaker application deployment feature has ended. For additional information, see https://docs.aws.amazon.com/robomaker/latest/dg/fleets.html."
)]
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterRobotOutput {
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fleet: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub robot: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeregisterRobotOutput {
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn fleet(&self) -> ::std::option::Option<&str> {
        self.fleet.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
    pub fn robot(&self) -> ::std::option::Option<&str> {
        self.robot.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeregisterRobotOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeregisterRobotOutput {
    /// Creates a new builder-style object to manufacture [`DeregisterRobotOutput`](crate::operation::deregister_robot::DeregisterRobotOutput).
    pub fn builder() -> crate::operation::deregister_robot::builders::DeregisterRobotOutputBuilder {
        crate::operation::deregister_robot::builders::DeregisterRobotOutputBuilder::default()
    }
}

/// A builder for [`DeregisterRobotOutput`](crate::operation::deregister_robot::DeregisterRobotOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterRobotOutputBuilder {
    pub(crate) fleet: ::std::option::Option<::std::string::String>,
    pub(crate) robot: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeregisterRobotOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn fleet(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn set_fleet(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn get_fleet(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet
    }
    /// <p>The Amazon Resource Name (ARN) of the robot.</p>
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeregisterRobotOutput`](crate::operation::deregister_robot::DeregisterRobotOutput).
    pub fn build(self) -> crate::operation::deregister_robot::DeregisterRobotOutput {
        crate::operation::deregister_robot::DeregisterRobotOutput {
            fleet: self.fleet,
            robot: self.robot,
            _request_id: self._request_id,
        }
    }
}
