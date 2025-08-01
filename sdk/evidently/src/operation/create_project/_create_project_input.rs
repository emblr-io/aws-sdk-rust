// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateProjectInput {
    /// <p>The name for the project.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An optional description of the project.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A structure that contains information about where Evidently is to store evaluation events for longer term storage, if you choose to do so. If you choose not to store these events, Evidently deletes them after using them to produce metrics and other experiment results that you can view.</p>
    pub data_delivery: ::std::option::Option<crate::types::ProjectDataDeliveryConfig>,
    /// <p>Use this parameter if the project will use <i>client-side evaluation powered by AppConfig</i>. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Evidently-client-side-evaluation.html"> Client-side evaluation - powered by AppConfig.</a></p>
    /// <p>This parameter is a structure that contains information about the AppConfig application and environment that will be used as for client-side evaluation.</p>
    /// <p>To create a project that uses client-side evaluation, you must have the <code>evidently:ExportProjectAsConfiguration</code> permission.</p>
    pub app_config_resource: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>,
    /// <p>Assigns one or more tags (key-value pairs) to the project.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with a project.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateProjectInput {
    /// <p>The name for the project.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An optional description of the project.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A structure that contains information about where Evidently is to store evaluation events for longer term storage, if you choose to do so. If you choose not to store these events, Evidently deletes them after using them to produce metrics and other experiment results that you can view.</p>
    pub fn data_delivery(&self) -> ::std::option::Option<&crate::types::ProjectDataDeliveryConfig> {
        self.data_delivery.as_ref()
    }
    /// <p>Use this parameter if the project will use <i>client-side evaluation powered by AppConfig</i>. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Evidently-client-side-evaluation.html"> Client-side evaluation - powered by AppConfig.</a></p>
    /// <p>This parameter is a structure that contains information about the AppConfig application and environment that will be used as for client-side evaluation.</p>
    /// <p>To create a project that uses client-side evaluation, you must have the <code>evidently:ExportProjectAsConfiguration</code> permission.</p>
    pub fn app_config_resource(&self) -> ::std::option::Option<&crate::types::ProjectAppConfigResourceConfig> {
        self.app_config_resource.as_ref()
    }
    /// <p>Assigns one or more tags (key-value pairs) to the project.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with a project.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateProjectInput {
    /// Creates a new builder-style object to manufacture [`CreateProjectInput`](crate::operation::create_project::CreateProjectInput).
    pub fn builder() -> crate::operation::create_project::builders::CreateProjectInputBuilder {
        crate::operation::create_project::builders::CreateProjectInputBuilder::default()
    }
}

/// A builder for [`CreateProjectInput`](crate::operation::create_project::CreateProjectInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateProjectInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) data_delivery: ::std::option::Option<crate::types::ProjectDataDeliveryConfig>,
    pub(crate) app_config_resource: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateProjectInputBuilder {
    /// <p>The name for the project.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the project.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the project.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
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
    /// <p>A structure that contains information about where Evidently is to store evaluation events for longer term storage, if you choose to do so. If you choose not to store these events, Evidently deletes them after using them to produce metrics and other experiment results that you can view.</p>
    pub fn data_delivery(mut self, input: crate::types::ProjectDataDeliveryConfig) -> Self {
        self.data_delivery = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains information about where Evidently is to store evaluation events for longer term storage, if you choose to do so. If you choose not to store these events, Evidently deletes them after using them to produce metrics and other experiment results that you can view.</p>
    pub fn set_data_delivery(mut self, input: ::std::option::Option<crate::types::ProjectDataDeliveryConfig>) -> Self {
        self.data_delivery = input;
        self
    }
    /// <p>A structure that contains information about where Evidently is to store evaluation events for longer term storage, if you choose to do so. If you choose not to store these events, Evidently deletes them after using them to produce metrics and other experiment results that you can view.</p>
    pub fn get_data_delivery(&self) -> &::std::option::Option<crate::types::ProjectDataDeliveryConfig> {
        &self.data_delivery
    }
    /// <p>Use this parameter if the project will use <i>client-side evaluation powered by AppConfig</i>. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Evidently-client-side-evaluation.html"> Client-side evaluation - powered by AppConfig.</a></p>
    /// <p>This parameter is a structure that contains information about the AppConfig application and environment that will be used as for client-side evaluation.</p>
    /// <p>To create a project that uses client-side evaluation, you must have the <code>evidently:ExportProjectAsConfiguration</code> permission.</p>
    pub fn app_config_resource(mut self, input: crate::types::ProjectAppConfigResourceConfig) -> Self {
        self.app_config_resource = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use this parameter if the project will use <i>client-side evaluation powered by AppConfig</i>. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Evidently-client-side-evaluation.html"> Client-side evaluation - powered by AppConfig.</a></p>
    /// <p>This parameter is a structure that contains information about the AppConfig application and environment that will be used as for client-side evaluation.</p>
    /// <p>To create a project that uses client-side evaluation, you must have the <code>evidently:ExportProjectAsConfiguration</code> permission.</p>
    pub fn set_app_config_resource(mut self, input: ::std::option::Option<crate::types::ProjectAppConfigResourceConfig>) -> Self {
        self.app_config_resource = input;
        self
    }
    /// <p>Use this parameter if the project will use <i>client-side evaluation powered by AppConfig</i>. Client-side evaluation allows your application to assign variations to user sessions locally instead of by calling the <a href="https://docs.aws.amazon.com/cloudwatchevidently/latest/APIReference/API_EvaluateFeature.html">EvaluateFeature</a> operation. This mitigates the latency and availability risks that come with an API call. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Evidently-client-side-evaluation.html"> Client-side evaluation - powered by AppConfig.</a></p>
    /// <p>This parameter is a structure that contains information about the AppConfig application and environment that will be used as for client-side evaluation.</p>
    /// <p>To create a project that uses client-side evaluation, you must have the <code>evidently:ExportProjectAsConfiguration</code> permission.</p>
    pub fn get_app_config_resource(&self) -> &::std::option::Option<crate::types::ProjectAppConfigResourceConfig> {
        &self.app_config_resource
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Assigns one or more tags (key-value pairs) to the project.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with a project.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Assigns one or more tags (key-value pairs) to the project.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with a project.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Assigns one or more tags (key-value pairs) to the project.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with a project.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateProjectInput`](crate::operation::create_project::CreateProjectInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_project::CreateProjectInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_project::CreateProjectInput {
            name: self.name,
            description: self.description,
            data_delivery: self.data_delivery,
            app_config_resource: self.app_config_resource,
            tags: self.tags,
        })
    }
}
