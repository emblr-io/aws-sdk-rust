// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the container, as part of model definition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerDefinition {
    /// <p>This parameter is ignored for models that contain only a <code>PrimaryContainer</code>.</p>
    /// <p>When a <code>ContainerDefinition</code> is part of an inference pipeline, the value of the parameter uniquely identifies the container for the purposes of logging and metrics. For information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/inference-pipeline-logs-metrics.html">Use Logs and Metrics to Monitor an Inference Pipeline</a>. If you don't specify a value for this parameter for a <code>ContainerDefinition</code> that is part of an inference pipeline, a unique name is automatically assigned based on the position of the <code>ContainerDefinition</code> in the pipeline. If you specify a value for the <code>ContainerHostName</code> for any <code>ContainerDefinition</code> that is part of an inference pipeline, you must specify a value for the <code>ContainerHostName</code> parameter of every <code>ContainerDefinition</code> in that pipeline.</p>
    pub container_hostname: ::std::option::Option<::std::string::String>,
    /// <p>The path where inference code is stored. This can be either in Amazon EC2 Container Registry or in a Docker registry that is accessible from the same VPC that you configure for your endpoint. If you are using your own custom algorithm instead of an algorithm provided by SageMaker, the inference code must meet SageMaker requirements. SageMaker supports both <code>registry/repository\[:tag\]</code> and <code>registry/repository\[@digest\]</code> image path formats. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html">Using Your Own Algorithms with Amazon SageMaker</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub image: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC). For information about storing containers in a private Docker registry, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms-containers-inference-private.html">Use a Private Docker Registry for Real-Time Inference Containers</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub image_config: ::std::option::Option<crate::types::ImageConfig>,
    /// <p>Whether the container hosts a single model or multiple models.</p>
    pub mode: ::std::option::Option<crate::types::ContainerMode>,
    /// <p>The S3 path where the model artifacts, which result from model training, are stored. This path must point to a single gzip compressed tar archive (.tar.gz suffix). The S3 path is required for SageMaker built-in algorithms, but not if you use your own algorithms. For more information on built-in algorithms, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-algo-docker-registry-paths.html">Common Parameters</a>.</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same region as the model or endpoint you are creating.</p>
    /// </note>
    /// <p>If you provide a value for this parameter, SageMaker uses Amazon Web Services Security Token Service to download model artifacts from the S3 path you provide. Amazon Web Services STS is activated in your Amazon Web Services account by default. If you previously deactivated Amazon Web Services STS for a region, you need to reactivate Amazon Web Services STS for that region. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html">Activating and Deactivating Amazon Web Services STS in an Amazon Web Services Region</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p><important>
    /// <p>If you use a built-in algorithm to create a model, SageMaker requires that you provide a S3 path to the model artifacts in <code>ModelDataUrl</code>.</p>
    /// </important>
    pub model_data_url: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the location of ML model data to deploy.</p><note>
    /// <p>Currently you cannot use <code>ModelDataSource</code> in conjunction with SageMaker batch transform, SageMaker serverless endpoints, SageMaker multi-model endpoints, and SageMaker Marketplace.</p>
    /// </note>
    pub model_data_source: ::std::option::Option<crate::types::ModelDataSource>,
    /// <p>Data sources that are available to your model in addition to the one that you specify for <code>ModelDataSource</code> when you use the <code>CreateModel</code> action.</p>
    pub additional_model_data_sources: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalModelDataSource>>,
    /// <p>The environment variables to set in the Docker container. Don't include any sensitive data in your environment variables.</p>
    /// <p>The maximum length of each key and value in the <code>Environment</code> map is 1024 bytes. The maximum length of all keys and values in the map, combined, is 32 KB. If you pass multiple containers to a <code>CreateModel</code> request, then the maximum length of all of their maps, combined, is also 32 KB.</p>
    pub environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The name or Amazon Resource Name (ARN) of the model package to use to create the model.</p>
    pub model_package_name: ::std::option::Option<::std::string::String>,
    /// <p>The inference specification name in the model package version.</p>
    pub inference_specification_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies additional configuration for multi-model endpoints.</p>
    pub multi_model_config: ::std::option::Option<crate::types::MultiModelConfig>,
}
impl ContainerDefinition {
    /// <p>This parameter is ignored for models that contain only a <code>PrimaryContainer</code>.</p>
    /// <p>When a <code>ContainerDefinition</code> is part of an inference pipeline, the value of the parameter uniquely identifies the container for the purposes of logging and metrics. For information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/inference-pipeline-logs-metrics.html">Use Logs and Metrics to Monitor an Inference Pipeline</a>. If you don't specify a value for this parameter for a <code>ContainerDefinition</code> that is part of an inference pipeline, a unique name is automatically assigned based on the position of the <code>ContainerDefinition</code> in the pipeline. If you specify a value for the <code>ContainerHostName</code> for any <code>ContainerDefinition</code> that is part of an inference pipeline, you must specify a value for the <code>ContainerHostName</code> parameter of every <code>ContainerDefinition</code> in that pipeline.</p>
    pub fn container_hostname(&self) -> ::std::option::Option<&str> {
        self.container_hostname.as_deref()
    }
    /// <p>The path where inference code is stored. This can be either in Amazon EC2 Container Registry or in a Docker registry that is accessible from the same VPC that you configure for your endpoint. If you are using your own custom algorithm instead of an algorithm provided by SageMaker, the inference code must meet SageMaker requirements. SageMaker supports both <code>registry/repository\[:tag\]</code> and <code>registry/repository\[@digest\]</code> image path formats. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html">Using Your Own Algorithms with Amazon SageMaker</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn image(&self) -> ::std::option::Option<&str> {
        self.image.as_deref()
    }
    /// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC). For information about storing containers in a private Docker registry, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms-containers-inference-private.html">Use a Private Docker Registry for Real-Time Inference Containers</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn image_config(&self) -> ::std::option::Option<&crate::types::ImageConfig> {
        self.image_config.as_ref()
    }
    /// <p>Whether the container hosts a single model or multiple models.</p>
    pub fn mode(&self) -> ::std::option::Option<&crate::types::ContainerMode> {
        self.mode.as_ref()
    }
    /// <p>The S3 path where the model artifacts, which result from model training, are stored. This path must point to a single gzip compressed tar archive (.tar.gz suffix). The S3 path is required for SageMaker built-in algorithms, but not if you use your own algorithms. For more information on built-in algorithms, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-algo-docker-registry-paths.html">Common Parameters</a>.</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same region as the model or endpoint you are creating.</p>
    /// </note>
    /// <p>If you provide a value for this parameter, SageMaker uses Amazon Web Services Security Token Service to download model artifacts from the S3 path you provide. Amazon Web Services STS is activated in your Amazon Web Services account by default. If you previously deactivated Amazon Web Services STS for a region, you need to reactivate Amazon Web Services STS for that region. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html">Activating and Deactivating Amazon Web Services STS in an Amazon Web Services Region</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p><important>
    /// <p>If you use a built-in algorithm to create a model, SageMaker requires that you provide a S3 path to the model artifacts in <code>ModelDataUrl</code>.</p>
    /// </important>
    pub fn model_data_url(&self) -> ::std::option::Option<&str> {
        self.model_data_url.as_deref()
    }
    /// <p>Specifies the location of ML model data to deploy.</p><note>
    /// <p>Currently you cannot use <code>ModelDataSource</code> in conjunction with SageMaker batch transform, SageMaker serverless endpoints, SageMaker multi-model endpoints, and SageMaker Marketplace.</p>
    /// </note>
    pub fn model_data_source(&self) -> ::std::option::Option<&crate::types::ModelDataSource> {
        self.model_data_source.as_ref()
    }
    /// <p>Data sources that are available to your model in addition to the one that you specify for <code>ModelDataSource</code> when you use the <code>CreateModel</code> action.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_model_data_sources.is_none()`.
    pub fn additional_model_data_sources(&self) -> &[crate::types::AdditionalModelDataSource] {
        self.additional_model_data_sources.as_deref().unwrap_or_default()
    }
    /// <p>The environment variables to set in the Docker container. Don't include any sensitive data in your environment variables.</p>
    /// <p>The maximum length of each key and value in the <code>Environment</code> map is 1024 bytes. The maximum length of all keys and values in the map, combined, is 32 KB. If you pass multiple containers to a <code>CreateModel</code> request, then the maximum length of all of their maps, combined, is also 32 KB.</p>
    pub fn environment(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.environment.as_ref()
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to use to create the model.</p>
    pub fn model_package_name(&self) -> ::std::option::Option<&str> {
        self.model_package_name.as_deref()
    }
    /// <p>The inference specification name in the model package version.</p>
    pub fn inference_specification_name(&self) -> ::std::option::Option<&str> {
        self.inference_specification_name.as_deref()
    }
    /// <p>Specifies additional configuration for multi-model endpoints.</p>
    pub fn multi_model_config(&self) -> ::std::option::Option<&crate::types::MultiModelConfig> {
        self.multi_model_config.as_ref()
    }
}
impl ContainerDefinition {
    /// Creates a new builder-style object to manufacture [`ContainerDefinition`](crate::types::ContainerDefinition).
    pub fn builder() -> crate::types::builders::ContainerDefinitionBuilder {
        crate::types::builders::ContainerDefinitionBuilder::default()
    }
}

/// A builder for [`ContainerDefinition`](crate::types::ContainerDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerDefinitionBuilder {
    pub(crate) container_hostname: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<::std::string::String>,
    pub(crate) image_config: ::std::option::Option<crate::types::ImageConfig>,
    pub(crate) mode: ::std::option::Option<crate::types::ContainerMode>,
    pub(crate) model_data_url: ::std::option::Option<::std::string::String>,
    pub(crate) model_data_source: ::std::option::Option<crate::types::ModelDataSource>,
    pub(crate) additional_model_data_sources: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalModelDataSource>>,
    pub(crate) environment: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) model_package_name: ::std::option::Option<::std::string::String>,
    pub(crate) inference_specification_name: ::std::option::Option<::std::string::String>,
    pub(crate) multi_model_config: ::std::option::Option<crate::types::MultiModelConfig>,
}
impl ContainerDefinitionBuilder {
    /// <p>This parameter is ignored for models that contain only a <code>PrimaryContainer</code>.</p>
    /// <p>When a <code>ContainerDefinition</code> is part of an inference pipeline, the value of the parameter uniquely identifies the container for the purposes of logging and metrics. For information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/inference-pipeline-logs-metrics.html">Use Logs and Metrics to Monitor an Inference Pipeline</a>. If you don't specify a value for this parameter for a <code>ContainerDefinition</code> that is part of an inference pipeline, a unique name is automatically assigned based on the position of the <code>ContainerDefinition</code> in the pipeline. If you specify a value for the <code>ContainerHostName</code> for any <code>ContainerDefinition</code> that is part of an inference pipeline, you must specify a value for the <code>ContainerHostName</code> parameter of every <code>ContainerDefinition</code> in that pipeline.</p>
    pub fn container_hostname(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_hostname = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This parameter is ignored for models that contain only a <code>PrimaryContainer</code>.</p>
    /// <p>When a <code>ContainerDefinition</code> is part of an inference pipeline, the value of the parameter uniquely identifies the container for the purposes of logging and metrics. For information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/inference-pipeline-logs-metrics.html">Use Logs and Metrics to Monitor an Inference Pipeline</a>. If you don't specify a value for this parameter for a <code>ContainerDefinition</code> that is part of an inference pipeline, a unique name is automatically assigned based on the position of the <code>ContainerDefinition</code> in the pipeline. If you specify a value for the <code>ContainerHostName</code> for any <code>ContainerDefinition</code> that is part of an inference pipeline, you must specify a value for the <code>ContainerHostName</code> parameter of every <code>ContainerDefinition</code> in that pipeline.</p>
    pub fn set_container_hostname(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_hostname = input;
        self
    }
    /// <p>This parameter is ignored for models that contain only a <code>PrimaryContainer</code>.</p>
    /// <p>When a <code>ContainerDefinition</code> is part of an inference pipeline, the value of the parameter uniquely identifies the container for the purposes of logging and metrics. For information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/inference-pipeline-logs-metrics.html">Use Logs and Metrics to Monitor an Inference Pipeline</a>. If you don't specify a value for this parameter for a <code>ContainerDefinition</code> that is part of an inference pipeline, a unique name is automatically assigned based on the position of the <code>ContainerDefinition</code> in the pipeline. If you specify a value for the <code>ContainerHostName</code> for any <code>ContainerDefinition</code> that is part of an inference pipeline, you must specify a value for the <code>ContainerHostName</code> parameter of every <code>ContainerDefinition</code> in that pipeline.</p>
    pub fn get_container_hostname(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_hostname
    }
    /// <p>The path where inference code is stored. This can be either in Amazon EC2 Container Registry or in a Docker registry that is accessible from the same VPC that you configure for your endpoint. If you are using your own custom algorithm instead of an algorithm provided by SageMaker, the inference code must meet SageMaker requirements. SageMaker supports both <code>registry/repository\[:tag\]</code> and <code>registry/repository\[@digest\]</code> image path formats. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html">Using Your Own Algorithms with Amazon SageMaker</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path where inference code is stored. This can be either in Amazon EC2 Container Registry or in a Docker registry that is accessible from the same VPC that you configure for your endpoint. If you are using your own custom algorithm instead of an algorithm provided by SageMaker, the inference code must meet SageMaker requirements. SageMaker supports both <code>registry/repository\[:tag\]</code> and <code>registry/repository\[@digest\]</code> image path formats. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html">Using Your Own Algorithms with Amazon SageMaker</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The path where inference code is stored. This can be either in Amazon EC2 Container Registry or in a Docker registry that is accessible from the same VPC that you configure for your endpoint. If you are using your own custom algorithm instead of an algorithm provided by SageMaker, the inference code must meet SageMaker requirements. SageMaker supports both <code>registry/repository\[:tag\]</code> and <code>registry/repository\[@digest\]</code> image path formats. For more information, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms.html">Using Your Own Algorithms with Amazon SageMaker</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC). For information about storing containers in a private Docker registry, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms-containers-inference-private.html">Use a Private Docker Registry for Real-Time Inference Containers</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn image_config(mut self, input: crate::types::ImageConfig) -> Self {
        self.image_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC). For information about storing containers in a private Docker registry, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms-containers-inference-private.html">Use a Private Docker Registry for Real-Time Inference Containers</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn set_image_config(mut self, input: ::std::option::Option<crate::types::ImageConfig>) -> Self {
        self.image_config = input;
        self
    }
    /// <p>Specifies whether the model container is in Amazon ECR or a private Docker registry accessible from your Amazon Virtual Private Cloud (VPC). For information about storing containers in a private Docker registry, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/your-algorithms-containers-inference-private.html">Use a Private Docker Registry for Real-Time Inference Containers</a>.</p><note>
    /// <p>The model artifacts in an Amazon S3 bucket and the Docker image for inference container in Amazon EC2 Container Registry must be in the same region as the model or endpoint you are creating.</p>
    /// </note>
    pub fn get_image_config(&self) -> &::std::option::Option<crate::types::ImageConfig> {
        &self.image_config
    }
    /// <p>Whether the container hosts a single model or multiple models.</p>
    pub fn mode(mut self, input: crate::types::ContainerMode) -> Self {
        self.mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the container hosts a single model or multiple models.</p>
    pub fn set_mode(mut self, input: ::std::option::Option<crate::types::ContainerMode>) -> Self {
        self.mode = input;
        self
    }
    /// <p>Whether the container hosts a single model or multiple models.</p>
    pub fn get_mode(&self) -> &::std::option::Option<crate::types::ContainerMode> {
        &self.mode
    }
    /// <p>The S3 path where the model artifacts, which result from model training, are stored. This path must point to a single gzip compressed tar archive (.tar.gz suffix). The S3 path is required for SageMaker built-in algorithms, but not if you use your own algorithms. For more information on built-in algorithms, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-algo-docker-registry-paths.html">Common Parameters</a>.</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same region as the model or endpoint you are creating.</p>
    /// </note>
    /// <p>If you provide a value for this parameter, SageMaker uses Amazon Web Services Security Token Service to download model artifacts from the S3 path you provide. Amazon Web Services STS is activated in your Amazon Web Services account by default. If you previously deactivated Amazon Web Services STS for a region, you need to reactivate Amazon Web Services STS for that region. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html">Activating and Deactivating Amazon Web Services STS in an Amazon Web Services Region</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p><important>
    /// <p>If you use a built-in algorithm to create a model, SageMaker requires that you provide a S3 path to the model artifacts in <code>ModelDataUrl</code>.</p>
    /// </important>
    pub fn model_data_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_data_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The S3 path where the model artifacts, which result from model training, are stored. This path must point to a single gzip compressed tar archive (.tar.gz suffix). The S3 path is required for SageMaker built-in algorithms, but not if you use your own algorithms. For more information on built-in algorithms, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-algo-docker-registry-paths.html">Common Parameters</a>.</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same region as the model or endpoint you are creating.</p>
    /// </note>
    /// <p>If you provide a value for this parameter, SageMaker uses Amazon Web Services Security Token Service to download model artifacts from the S3 path you provide. Amazon Web Services STS is activated in your Amazon Web Services account by default. If you previously deactivated Amazon Web Services STS for a region, you need to reactivate Amazon Web Services STS for that region. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html">Activating and Deactivating Amazon Web Services STS in an Amazon Web Services Region</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p><important>
    /// <p>If you use a built-in algorithm to create a model, SageMaker requires that you provide a S3 path to the model artifacts in <code>ModelDataUrl</code>.</p>
    /// </important>
    pub fn set_model_data_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_data_url = input;
        self
    }
    /// <p>The S3 path where the model artifacts, which result from model training, are stored. This path must point to a single gzip compressed tar archive (.tar.gz suffix). The S3 path is required for SageMaker built-in algorithms, but not if you use your own algorithms. For more information on built-in algorithms, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/sagemaker-algo-docker-registry-paths.html">Common Parameters</a>.</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same region as the model or endpoint you are creating.</p>
    /// </note>
    /// <p>If you provide a value for this parameter, SageMaker uses Amazon Web Services Security Token Service to download model artifacts from the S3 path you provide. Amazon Web Services STS is activated in your Amazon Web Services account by default. If you previously deactivated Amazon Web Services STS for a region, you need to reactivate Amazon Web Services STS for that region. For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_enable-regions.html">Activating and Deactivating Amazon Web Services STS in an Amazon Web Services Region</a> in the <i>Amazon Web Services Identity and Access Management User Guide</i>.</p><important>
    /// <p>If you use a built-in algorithm to create a model, SageMaker requires that you provide a S3 path to the model artifacts in <code>ModelDataUrl</code>.</p>
    /// </important>
    pub fn get_model_data_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_data_url
    }
    /// <p>Specifies the location of ML model data to deploy.</p><note>
    /// <p>Currently you cannot use <code>ModelDataSource</code> in conjunction with SageMaker batch transform, SageMaker serverless endpoints, SageMaker multi-model endpoints, and SageMaker Marketplace.</p>
    /// </note>
    pub fn model_data_source(mut self, input: crate::types::ModelDataSource) -> Self {
        self.model_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the location of ML model data to deploy.</p><note>
    /// <p>Currently you cannot use <code>ModelDataSource</code> in conjunction with SageMaker batch transform, SageMaker serverless endpoints, SageMaker multi-model endpoints, and SageMaker Marketplace.</p>
    /// </note>
    pub fn set_model_data_source(mut self, input: ::std::option::Option<crate::types::ModelDataSource>) -> Self {
        self.model_data_source = input;
        self
    }
    /// <p>Specifies the location of ML model data to deploy.</p><note>
    /// <p>Currently you cannot use <code>ModelDataSource</code> in conjunction with SageMaker batch transform, SageMaker serverless endpoints, SageMaker multi-model endpoints, and SageMaker Marketplace.</p>
    /// </note>
    pub fn get_model_data_source(&self) -> &::std::option::Option<crate::types::ModelDataSource> {
        &self.model_data_source
    }
    /// Appends an item to `additional_model_data_sources`.
    ///
    /// To override the contents of this collection use [`set_additional_model_data_sources`](Self::set_additional_model_data_sources).
    ///
    /// <p>Data sources that are available to your model in addition to the one that you specify for <code>ModelDataSource</code> when you use the <code>CreateModel</code> action.</p>
    pub fn additional_model_data_sources(mut self, input: crate::types::AdditionalModelDataSource) -> Self {
        let mut v = self.additional_model_data_sources.unwrap_or_default();
        v.push(input);
        self.additional_model_data_sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>Data sources that are available to your model in addition to the one that you specify for <code>ModelDataSource</code> when you use the <code>CreateModel</code> action.</p>
    pub fn set_additional_model_data_sources(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AdditionalModelDataSource>>,
    ) -> Self {
        self.additional_model_data_sources = input;
        self
    }
    /// <p>Data sources that are available to your model in addition to the one that you specify for <code>ModelDataSource</code> when you use the <code>CreateModel</code> action.</p>
    pub fn get_additional_model_data_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdditionalModelDataSource>> {
        &self.additional_model_data_sources
    }
    /// Adds a key-value pair to `environment`.
    ///
    /// To override the contents of this collection use [`set_environment`](Self::set_environment).
    ///
    /// <p>The environment variables to set in the Docker container. Don't include any sensitive data in your environment variables.</p>
    /// <p>The maximum length of each key and value in the <code>Environment</code> map is 1024 bytes. The maximum length of all keys and values in the map, combined, is 32 KB. If you pass multiple containers to a <code>CreateModel</code> request, then the maximum length of all of their maps, combined, is also 32 KB.</p>
    pub fn environment(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.environment.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.environment = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The environment variables to set in the Docker container. Don't include any sensitive data in your environment variables.</p>
    /// <p>The maximum length of each key and value in the <code>Environment</code> map is 1024 bytes. The maximum length of all keys and values in the map, combined, is 32 KB. If you pass multiple containers to a <code>CreateModel</code> request, then the maximum length of all of their maps, combined, is also 32 KB.</p>
    pub fn set_environment(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.environment = input;
        self
    }
    /// <p>The environment variables to set in the Docker container. Don't include any sensitive data in your environment variables.</p>
    /// <p>The maximum length of each key and value in the <code>Environment</code> map is 1024 bytes. The maximum length of all keys and values in the map, combined, is 32 KB. If you pass multiple containers to a <code>CreateModel</code> request, then the maximum length of all of their maps, combined, is also 32 KB.</p>
    pub fn get_environment(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.environment
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to use to create the model.</p>
    pub fn model_package_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_package_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to use to create the model.</p>
    pub fn set_model_package_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_package_name = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the model package to use to create the model.</p>
    pub fn get_model_package_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_package_name
    }
    /// <p>The inference specification name in the model package version.</p>
    pub fn inference_specification_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_specification_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The inference specification name in the model package version.</p>
    pub fn set_inference_specification_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_specification_name = input;
        self
    }
    /// <p>The inference specification name in the model package version.</p>
    pub fn get_inference_specification_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_specification_name
    }
    /// <p>Specifies additional configuration for multi-model endpoints.</p>
    pub fn multi_model_config(mut self, input: crate::types::MultiModelConfig) -> Self {
        self.multi_model_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies additional configuration for multi-model endpoints.</p>
    pub fn set_multi_model_config(mut self, input: ::std::option::Option<crate::types::MultiModelConfig>) -> Self {
        self.multi_model_config = input;
        self
    }
    /// <p>Specifies additional configuration for multi-model endpoints.</p>
    pub fn get_multi_model_config(&self) -> &::std::option::Option<crate::types::MultiModelConfig> {
        &self.multi_model_config
    }
    /// Consumes the builder and constructs a [`ContainerDefinition`](crate::types::ContainerDefinition).
    pub fn build(self) -> crate::types::ContainerDefinition {
        crate::types::ContainerDefinition {
            container_hostname: self.container_hostname,
            image: self.image,
            image_config: self.image_config,
            mode: self.mode,
            model_data_url: self.model_data_url,
            model_data_source: self.model_data_source,
            additional_model_data_sources: self.additional_model_data_sources,
            environment: self.environment,
            model_package_name: self.model_package_name,
            inference_specification_name: self.inference_specification_name,
            multi_model_config: self.multi_model_config,
        }
    }
}
