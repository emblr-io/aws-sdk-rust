// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A revision for an Lambda or Amazon ECS deployment that is a YAML-formatted or JSON-formatted string. For Lambda and Amazon ECS deployments, the revision is the same as the AppSpec file. This method replaces the deprecated <code>RawString</code> data type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppSpecContent {
    /// <p>The YAML-formatted or JSON-formatted revision string.</p>
    /// <p>For an Lambda deployment, the content includes a Lambda function name, the alias for its original version, and the alias for its replacement version. The deployment shifts traffic from the original version of the Lambda function to the replacement version.</p>
    /// <p>For an Amazon ECS deployment, the content includes the task name, information about the load balancer that serves traffic to the container, and more.</p>
    /// <p>For both types of deployments, the content can specify Lambda functions that run at specified hooks, such as <code>BeforeInstall</code>, during a deployment.</p>
    pub content: ::std::option::Option<::std::string::String>,
    /// <p>The SHA256 hash value of the revision content.</p>
    pub sha256: ::std::option::Option<::std::string::String>,
}
impl AppSpecContent {
    /// <p>The YAML-formatted or JSON-formatted revision string.</p>
    /// <p>For an Lambda deployment, the content includes a Lambda function name, the alias for its original version, and the alias for its replacement version. The deployment shifts traffic from the original version of the Lambda function to the replacement version.</p>
    /// <p>For an Amazon ECS deployment, the content includes the task name, information about the load balancer that serves traffic to the container, and more.</p>
    /// <p>For both types of deployments, the content can specify Lambda functions that run at specified hooks, such as <code>BeforeInstall</code>, during a deployment.</p>
    pub fn content(&self) -> ::std::option::Option<&str> {
        self.content.as_deref()
    }
    /// <p>The SHA256 hash value of the revision content.</p>
    pub fn sha256(&self) -> ::std::option::Option<&str> {
        self.sha256.as_deref()
    }
}
impl AppSpecContent {
    /// Creates a new builder-style object to manufacture [`AppSpecContent`](crate::types::AppSpecContent).
    pub fn builder() -> crate::types::builders::AppSpecContentBuilder {
        crate::types::builders::AppSpecContentBuilder::default()
    }
}

/// A builder for [`AppSpecContent`](crate::types::AppSpecContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppSpecContentBuilder {
    pub(crate) content: ::std::option::Option<::std::string::String>,
    pub(crate) sha256: ::std::option::Option<::std::string::String>,
}
impl AppSpecContentBuilder {
    /// <p>The YAML-formatted or JSON-formatted revision string.</p>
    /// <p>For an Lambda deployment, the content includes a Lambda function name, the alias for its original version, and the alias for its replacement version. The deployment shifts traffic from the original version of the Lambda function to the replacement version.</p>
    /// <p>For an Amazon ECS deployment, the content includes the task name, information about the load balancer that serves traffic to the container, and more.</p>
    /// <p>For both types of deployments, the content can specify Lambda functions that run at specified hooks, such as <code>BeforeInstall</code>, during a deployment.</p>
    pub fn content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The YAML-formatted or JSON-formatted revision string.</p>
    /// <p>For an Lambda deployment, the content includes a Lambda function name, the alias for its original version, and the alias for its replacement version. The deployment shifts traffic from the original version of the Lambda function to the replacement version.</p>
    /// <p>For an Amazon ECS deployment, the content includes the task name, information about the load balancer that serves traffic to the container, and more.</p>
    /// <p>For both types of deployments, the content can specify Lambda functions that run at specified hooks, such as <code>BeforeInstall</code>, during a deployment.</p>
    pub fn set_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content = input;
        self
    }
    /// <p>The YAML-formatted or JSON-formatted revision string.</p>
    /// <p>For an Lambda deployment, the content includes a Lambda function name, the alias for its original version, and the alias for its replacement version. The deployment shifts traffic from the original version of the Lambda function to the replacement version.</p>
    /// <p>For an Amazon ECS deployment, the content includes the task name, information about the load balancer that serves traffic to the container, and more.</p>
    /// <p>For both types of deployments, the content can specify Lambda functions that run at specified hooks, such as <code>BeforeInstall</code>, during a deployment.</p>
    pub fn get_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.content
    }
    /// <p>The SHA256 hash value of the revision content.</p>
    pub fn sha256(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sha256 = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SHA256 hash value of the revision content.</p>
    pub fn set_sha256(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sha256 = input;
        self
    }
    /// <p>The SHA256 hash value of the revision content.</p>
    pub fn get_sha256(&self) -> &::std::option::Option<::std::string::String> {
        &self.sha256
    }
    /// Consumes the builder and constructs a [`AppSpecContent`](crate::types::AppSpecContent).
    pub fn build(self) -> crate::types::AppSpecContent {
        crate::types::AppSpecContent {
            content: self.content,
            sha256: self.sha256,
        }
    }
}
