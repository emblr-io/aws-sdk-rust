// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateProjectInput {
    /// <p>The name or ARN of the project to update.</p>
    pub project: ::std::option::Option<::std::string::String>,
    /// <p>Use this parameter if the project will use client-side evaluation powered by AppConfig. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. allows you to</p>
    /// <p>This parameter is a structure that contains information about the AppConfig application that will be used for client-side evaluation.</p>
    pub app_config_resource: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>,
    /// <p>An optional description of the project.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInput {
    /// <p>The name or ARN of the project to update.</p>
    pub fn project(&self) -> ::std::option::Option<&str> {
        self.project.as_deref()
    }
    /// <p>Use this parameter if the project will use client-side evaluation powered by AppConfig. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. allows you to</p>
    /// <p>This parameter is a structure that contains information about the AppConfig application that will be used for client-side evaluation.</p>
    pub fn app_config_resource(&self) -> ::std::option::Option<&crate::types::ProjectAppConfigResourceConfig> {
        self.app_config_resource.as_ref()
    }
    /// <p>An optional description of the project.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateProjectInput {
    /// Creates a new builder-style object to manufacture [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn builder() -> crate::operation::update_project::builders::UpdateProjectInputBuilder {
        crate::operation::update_project::builders::UpdateProjectInputBuilder::default()
    }
}

/// A builder for [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateProjectInputBuilder {
    pub(crate) project: ::std::option::Option<::std::string::String>,
    pub(crate) app_config_resource: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateProjectInputBuilder {
    /// <p>The name or ARN of the project to update.</p>
    /// This field is required.
    pub fn project(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.project = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or ARN of the project to update.</p>
    pub fn set_project(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.project = input;
        self
    }
    /// <p>The name or ARN of the project to update.</p>
    pub fn get_project(&self) -> &::std::option::Option<::std::string::String> {
        &self.project
    }
    /// <p>Use this parameter if the project will use client-side evaluation powered by AppConfig. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. allows you to</p>
    /// <p>This parameter is a structure that contains information about the AppConfig application that will be used for client-side evaluation.</p>
    pub fn app_config_resource(mut self, input: crate::types::ProjectAppConfigResourceConfig) -> Self {
        self.app_config_resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this parameter if the project will use client-side evaluation powered by AppConfig. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. allows you to</p>
    /// <p>This parameter is a structure that contains information about the AppConfig application that will be used for client-side evaluation.</p>
    pub fn set_app_config_resource(mut self, input: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>) -> Self {
        self.app_config_resource = input;
        self
    }
    /// <p>Use this parameter if the project will use client-side evaluation powered by AppConfig. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. allows you to</p>
    /// <p>This parameter is a structure that contains information about the AppConfig application that will be used for client-side evaluation.</p>
    pub fn get_app_config_resource(&self) -> &::std::option::Option<crate::types::ProjectAppConfigResourceConfig> {
        &self.app_config_resource
    }
    /// <p>An optional description of the project.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description of the project.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An optional description of the project.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateProjectInput`](crate::operation::update_project::UpdateProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_project::UpdateProjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_project::UpdateProjectInput {
            project: self.project,
            app_config_resource: self.app_config_resource,
            description: self.description,
        })
    }
}
