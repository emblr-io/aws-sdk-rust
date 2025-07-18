// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartSimulationOutput {
    /// <p>The Amazon Resource Name (ARN) of the simulation. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>A universally unique identifier (UUID) for this simulation.</p>
    pub execution_id: ::std::option::Option<::std::string::String>,
    /// <p>The time when the simulation was created, expressed as the number of seconds and milliseconds in UTC since the Unix epoch (0:0:0.000, January 1, 1970).</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StartSimulationOutput {
    /// <p>The Amazon Resource Name (ARN) of the simulation. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>A universally unique identifier (UUID) for this simulation.</p>
    pub fn execution_id(&self) -> ::std::option::Option<&str> {
        self.execution_id.as_deref()
    }
    /// <p>The time when the simulation was created, expressed as the number of seconds and milliseconds in UTC since the Unix epoch (0:0:0.000, January 1, 1970).</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for StartSimulationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartSimulationOutput {
    /// Creates a new builder-style object to manufacture [`StartSimulationOutput`](crate::operation::start_simulation::StartSimulationOutput).
    pub fn builder() -> crate::operation::start_simulation::builders::StartSimulationOutputBuilder {
        crate::operation::start_simulation::builders::StartSimulationOutputBuilder::default()
    }
}

/// A builder for [`StartSimulationOutput`](crate::operation::start_simulation::StartSimulationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartSimulationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) execution_id: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl StartSimulationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the simulation. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the simulation. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the simulation. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A universally unique identifier (UUID) for this simulation.</p>
    pub fn execution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A universally unique identifier (UUID) for this simulation.</p>
    pub fn set_execution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_id = input;
        self
    }
    /// <p>A universally unique identifier (UUID) for this simulation.</p>
    pub fn get_execution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_id
    }
    /// <p>The time when the simulation was created, expressed as the number of seconds and milliseconds in UTC since the Unix epoch (0:0:0.000, January 1, 1970).</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the simulation was created, expressed as the number of seconds and milliseconds in UTC since the Unix epoch (0:0:0.000, January 1, 1970).</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time when the simulation was created, expressed as the number of seconds and milliseconds in UTC since the Unix epoch (0:0:0.000, January 1, 1970).</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartSimulationOutput`](crate::operation::start_simulation::StartSimulationOutput).
    pub fn build(self) -> crate::operation::start_simulation::StartSimulationOutput {
        crate::operation::start_simulation::StartSimulationOutput {
            arn: self.arn,
            execution_id: self.execution_id,
            creation_time: self.creation_time,
            _request_id: self._request_id,
        }
    }
}
