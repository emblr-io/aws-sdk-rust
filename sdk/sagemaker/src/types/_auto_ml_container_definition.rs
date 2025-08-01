// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of container definitions that describe the different containers that make up an AutoML candidate. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoMlContainerDefinition {
    /// <p>The Amazon Elastic Container Registry (Amazon ECR) path of the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub image: ::std::option::Option<::std::string::String>,
    /// <p>The location of the model artifacts. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub model_data_url: ::std::option::Option<::std::string::String>,
    /// <p>The environment variables to set in the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AutoMlContainerDefinition {
    /// <p>The Amazon Elastic Container Registry (Amazon ECR) path of the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn image(&self) -> ::std::option::Option<&str> {
        self.image.as_deref()
    }
    /// <p>The location of the model artifacts. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn model_data_url(&self) -> ::std::option::Option<&str> {
        self.model_data_url.as_deref()
    }
    /// <p>The environment variables to set in the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn environment(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.environment.as_ref()
    }
}
impl AutoMlContainerDefinition {
    /// Creates a new builder-style object to manufacture [`AutoMlContainerDefinition`](crate::types::AutoMlContainerDefinition).
    pub fn builder() -> crate::types::builders::AutoMlContainerDefinitionBuilder {
        crate::types::builders::AutoMlContainerDefinitionBuilder::default()
    }
}

/// A builder for [`AutoMlContainerDefinition`](crate::types::AutoMlContainerDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoMlContainerDefinitionBuilder {
    pub(crate) image: ::std::option::Option<::std::string::String>,
    pub(crate) model_data_url: ::std::option::Option<::std::string::String>,
    pub(crate) environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AutoMlContainerDefinitionBuilder {
    /// <p>The Amazon Elastic Container Registry (Amazon ECR) path of the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    /// This field is required.
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Elastic Container Registry (Amazon ECR) path of the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The Amazon Elastic Container Registry (Amazon ECR) path of the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// <p>The location of the model artifacts. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    /// This field is required.
    pub fn model_data_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_data_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location of the model artifacts. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn set_model_data_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_data_url = input;
        self
    }
    /// <p>The location of the model artifacts. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn get_model_data_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_data_url
    }
    /// Adds a key-value pair to `environment`.
    ///
    /// To override the contents of this collection use [`set_environment`](Self::set_environment).
    ///
    /// <p>The environment variables to set in the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn environment(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.environment.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.environment = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The environment variables to set in the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn set_environment(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.environment = input;
        self
    }
    /// <p>The environment variables to set in the container. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_ContainerDefinition.html"> ContainerDefinition</a>.</p>
    pub fn get_environment(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.environment
    }
    /// Consumes the builder and constructs a [`AutoMlContainerDefinition`](crate::types::AutoMlContainerDefinition).
    pub fn build(self) -> crate::types::AutoMlContainerDefinition {
        crate::types::AutoMlContainerDefinition {
            image: self.image,
            model_data_url: self.model_data_url,
            environment: self.environment,
        }
    }
}
