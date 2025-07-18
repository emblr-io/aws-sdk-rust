// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartLaunchInput {
    /// <p>The name or ARN of the project that contains the launch to start.</p>
    pub project: ::std::option::Option<::std::string::String>,
    /// <p>The name of the launch to start.</p>
    pub launch: ::std::option::Option<::std::string::String>,
}
impl StartLaunchInput {
    /// <p>The name or ARN of the project that contains the launch to start.</p>
    pub fn project(&self) -> ::std::option::Option<&str> {
        self.project.as_deref()
    }
    /// <p>The name of the launch to start.</p>
    pub fn launch(&self) -> ::std::option::Option<&str> {
        self.launch.as_deref()
    }
}
impl StartLaunchInput {
    /// Creates a new builder-style object to manufacture [`StartLaunchInput`](crate::operation::start_launch::StartLaunchInput).
    pub fn builder() -> crate::operation::start_launch::builders::StartLaunchInputBuilder {
        crate::operation::start_launch::builders::StartLaunchInputBuilder::default()
    }
}

/// A builder for [`StartLaunchInput`](crate::operation::start_launch::StartLaunchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartLaunchInputBuilder {
    pub(crate) project: ::std::option::Option<::std::string::String>,
    pub(crate) launch: ::std::option::Option<::std::string::String>,
}
impl StartLaunchInputBuilder {
    /// <p>The name or ARN of the project that contains the launch to start.</p>
    /// This field is required.
    pub fn project(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the project that contains the launch to start.</p>
    pub fn set_project(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project = input;
        self
    }
    /// <p>The name or ARN of the project that contains the launch to start.</p>
    pub fn get_project(&self) -> &::std::option::Option<::std::string::String> {
        &self.project
    }
    /// <p>The name of the launch to start.</p>
    /// This field is required.
    pub fn launch(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.launch = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the launch to start.</p>
    pub fn set_launch(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.launch = input;
        self
    }
    /// <p>The name of the launch to start.</p>
    pub fn get_launch(&self) -> &::std::option::Option<::std::string::String> {
        &self.launch
    }
    /// Consumes the builder and constructs a [`StartLaunchInput`](crate::operation::start_launch::StartLaunchInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::start_launch::StartLaunchInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_launch::StartLaunchInput {
            project: self.project,
            launch: self.launch,
        })
    }
}
