// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information required to run the <code>containerAction</code> to produce dataset contents.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerDatasetAction {
    /// <p>The ARN of the Docker container stored in your account. The Docker container contains an application and required support libraries and is used to generate dataset contents.</p>
    pub image: ::std::string::String,
    /// <p>The ARN of the role that gives permission to the system to access required resources to run the <code>containerAction</code>. This includes, at minimum, permission to retrieve the dataset contents that are the input to the containerized application.</p>
    pub execution_role_arn: ::std::string::String,
    /// <p>Configuration of the resource that executes the <code>containerAction</code>.</p>
    pub resource_configuration: ::std::option::Option<crate::types::ResourceConfiguration>,
    /// <p>The values of variables used in the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of <code>stringValue</code>, <code>datasetContentVersionValue</code>, or <code>outputFileUriValue</code>.</p>
    pub variables: ::std::option::Option<::std::vec::Vec<crate::types::Variable>>,
}
impl ContainerDatasetAction {
    /// <p>The ARN of the Docker container stored in your account. The Docker container contains an application and required support libraries and is used to generate dataset contents.</p>
    pub fn image(&self) -> &str {
        use std::ops::Deref;
        self.image.deref()
    }
    /// <p>The ARN of the role that gives permission to the system to access required resources to run the <code>containerAction</code>. This includes, at minimum, permission to retrieve the dataset contents that are the input to the containerized application.</p>
    pub fn execution_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.execution_role_arn.deref()
    }
    /// <p>Configuration of the resource that executes the <code>containerAction</code>.</p>
    pub fn resource_configuration(&self) -> ::std::option::Option<&crate::types::ResourceConfiguration> {
        self.resource_configuration.as_ref()
    }
    /// <p>The values of variables used in the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of <code>stringValue</code>, <code>datasetContentVersionValue</code>, or <code>outputFileUriValue</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.variables.is_none()`.
    pub fn variables(&self) -> &[crate::types::Variable] {
        self.variables.as_deref().unwrap_or_default()
    }
}
impl ContainerDatasetAction {
    /// Creates a new builder-style object to manufacture [`ContainerDatasetAction`](crate::types::ContainerDatasetAction).
    pub fn builder() -> crate::types::builders::ContainerDatasetActionBuilder {
        crate::types::builders::ContainerDatasetActionBuilder::default()
    }
}

/// A builder for [`ContainerDatasetAction`](crate::types::ContainerDatasetAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerDatasetActionBuilder {
    pub(crate) image: ::std::option::Option<::std::string::String>,
    pub(crate) execution_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) resource_configuration: ::std::option::Option<crate::types::ResourceConfiguration>,
    pub(crate) variables: ::std::option::Option<::std::vec::Vec<crate::types::Variable>>,
}
impl ContainerDatasetActionBuilder {
    /// <p>The ARN of the Docker container stored in your account. The Docker container contains an application and required support libraries and is used to generate dataset contents.</p>
    /// This field is required.
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Docker container stored in your account. The Docker container contains an application and required support libraries and is used to generate dataset contents.</p>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The ARN of the Docker container stored in your account. The Docker container contains an application and required support libraries and is used to generate dataset contents.</p>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// <p>The ARN of the role that gives permission to the system to access required resources to run the <code>containerAction</code>. This includes, at minimum, permission to retrieve the dataset contents that are the input to the containerized application.</p>
    /// This field is required.
    pub fn execution_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role that gives permission to the system to access required resources to run the <code>containerAction</code>. This includes, at minimum, permission to retrieve the dataset contents that are the input to the containerized application.</p>
    pub fn set_execution_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role_arn = input;
        self
    }
    /// <p>The ARN of the role that gives permission to the system to access required resources to run the <code>containerAction</code>. This includes, at minimum, permission to retrieve the dataset contents that are the input to the containerized application.</p>
    pub fn get_execution_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role_arn
    }
    /// <p>Configuration of the resource that executes the <code>containerAction</code>.</p>
    /// This field is required.
    pub fn resource_configuration(mut self, input: crate::types::ResourceConfiguration) -> Self {
        self.resource_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration of the resource that executes the <code>containerAction</code>.</p>
    pub fn set_resource_configuration(mut self, input: ::std::option::Option<crate::types::ResourceConfiguration>) -> Self {
        self.resource_configuration = input;
        self
    }
    /// <p>Configuration of the resource that executes the <code>containerAction</code>.</p>
    pub fn get_resource_configuration(&self) -> &::std::option::Option<crate::types::ResourceConfiguration> {
        &self.resource_configuration
    }
    /// Appends an item to `variables`.
    ///
    /// To override the contents of this collection use [`set_variables`](Self::set_variables).
    ///
    /// <p>The values of variables used in the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of <code>stringValue</code>, <code>datasetContentVersionValue</code>, or <code>outputFileUriValue</code>.</p>
    pub fn variables(mut self, input: crate::types::Variable) -> Self {
        let mut v = self.variables.unwrap_or_default();
        v.push(input);
        self.variables = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values of variables used in the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of <code>stringValue</code>, <code>datasetContentVersionValue</code>, or <code>outputFileUriValue</code>.</p>
    pub fn set_variables(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Variable>>) -> Self {
        self.variables = input;
        self
    }
    /// <p>The values of variables used in the context of the execution of the containerized application (basically, parameters passed to the application). Each variable must have a name and a value given by one of <code>stringValue</code>, <code>datasetContentVersionValue</code>, or <code>outputFileUriValue</code>.</p>
    pub fn get_variables(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Variable>> {
        &self.variables
    }
    /// Consumes the builder and constructs a [`ContainerDatasetAction`](crate::types::ContainerDatasetAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`image`](crate::types::builders::ContainerDatasetActionBuilder::image)
    /// - [`execution_role_arn`](crate::types::builders::ContainerDatasetActionBuilder::execution_role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::ContainerDatasetAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ContainerDatasetAction {
            image: self.image.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "image",
                    "image was not specified but it is required when building ContainerDatasetAction",
                )
            })?,
            execution_role_arn: self.execution_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "execution_role_arn",
                    "execution_role_arn was not specified but it is required when building ContainerDatasetAction",
                )
            })?,
            resource_configuration: self.resource_configuration,
            variables: self.variables,
        })
    }
}
