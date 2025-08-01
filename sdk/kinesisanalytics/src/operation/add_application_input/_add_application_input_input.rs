// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddApplicationInputInput {
    /// <p>Name of your existing Amazon Kinesis Analytics application to which you want to add the streaming source.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>Current version of your Amazon Kinesis Analytics application. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to find the current application version.</p>
    pub current_application_version_id: ::std::option::Option<i64>,
    /// <p>The <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_Input.html">Input</a> to add.</p>
    pub input: ::std::option::Option<crate::types::Input>,
}
impl AddApplicationInputInput {
    /// <p>Name of your existing Amazon Kinesis Analytics application to which you want to add the streaming source.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>Current version of your Amazon Kinesis Analytics application. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to find the current application version.</p>
    pub fn current_application_version_id(&self) -> ::std::option::Option<i64> {
        self.current_application_version_id
    }
    /// <p>The <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_Input.html">Input</a> to add.</p>
    pub fn input(&self) -> ::std::option::Option<&crate::types::Input> {
        self.input.as_ref()
    }
}
impl AddApplicationInputInput {
    /// Creates a new builder-style object to manufacture [`AddApplicationInputInput`](crate::operation::add_application_input::AddApplicationInputInput).
    pub fn builder() -> crate::operation::add_application_input::builders::AddApplicationInputInputBuilder {
        crate::operation::add_application_input::builders::AddApplicationInputInputBuilder::default()
    }
}

/// A builder for [`AddApplicationInputInput`](crate::operation::add_application_input::AddApplicationInputInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddApplicationInputInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) current_application_version_id: ::std::option::Option<i64>,
    pub(crate) input: ::std::option::Option<crate::types::Input>,
}
impl AddApplicationInputInputBuilder {
    /// <p>Name of your existing Amazon Kinesis Analytics application to which you want to add the streaming source.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of your existing Amazon Kinesis Analytics application to which you want to add the streaming source.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>Name of your existing Amazon Kinesis Analytics application to which you want to add the streaming source.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>Current version of your Amazon Kinesis Analytics application. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to find the current application version.</p>
    /// This field is required.
    pub fn current_application_version_id(mut self, input: i64) -> Self {
        self.current_application_version_id = ::std::option::Option::Some(input);
        self
    }
    /// <p>Current version of your Amazon Kinesis Analytics application. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to find the current application version.</p>
    pub fn set_current_application_version_id(mut self, input: ::std::option::Option<i64>) -> Self {
        self.current_application_version_id = input;
        self
    }
    /// <p>Current version of your Amazon Kinesis Analytics application. You can use the <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_DescribeApplication.html">DescribeApplication</a> operation to find the current application version.</p>
    pub fn get_current_application_version_id(&self) -> &::std::option::Option<i64> {
        &self.current_application_version_id
    }
    /// <p>The <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_Input.html">Input</a> to add.</p>
    /// This field is required.
    pub fn input(mut self, input: crate::types::Input) -> Self {
        self.input = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_Input.html">Input</a> to add.</p>
    pub fn set_input(mut self, input: ::std::option::Option<crate::types::Input>) -> Self {
        self.input = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/kinesisanalytics/latest/dev/API_Input.html">Input</a> to add.</p>
    pub fn get_input(&self) -> &::std::option::Option<crate::types::Input> {
        &self.input
    }
    /// Consumes the builder and constructs a [`AddApplicationInputInput`](crate::operation::add_application_input::AddApplicationInputInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::add_application_input::AddApplicationInputInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::add_application_input::AddApplicationInputInput {
            application_name: self.application_name,
            current_application_version_id: self.current_application_version_id,
            input: self.input,
        })
    }
}
