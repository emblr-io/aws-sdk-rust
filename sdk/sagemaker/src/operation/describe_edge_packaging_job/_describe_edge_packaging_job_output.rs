// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEdgePackagingJobOutput {
    /// <p>The Amazon Resource Name (ARN) of the edge packaging job.</p>
    pub edge_packaging_job_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the edge packaging job.</p>
    pub edge_packaging_job_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the SageMaker Neo compilation job that is used to locate model artifacts that are being packaged.</p>
    pub compilation_job_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the model.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
    /// <p>The version of the model.</p>
    pub model_version: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to download and upload the model, and to contact Neo.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The output configuration for the edge packaging job.</p>
    pub output_config: ::std::option::Option<crate::types::EdgeOutputConfig>,
    /// <p>The Amazon Web Services KMS key to use when encrypting the EBS volume the job run on.</p>
    pub resource_key: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the packaging job.</p>
    pub edge_packaging_job_status: ::std::option::Option<crate::types::EdgePackagingJobStatus>,
    /// <p>Returns a message describing the job status and error messages.</p>
    pub edge_packaging_job_status_message: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the packaging job was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp of when the job was last updated.</p>
    pub last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Simple Storage (S3) URI where model artifacts ares stored.</p>
    pub model_artifact: ::std::option::Option<::std::string::String>,
    /// <p>The signature document of files in the model artifact.</p>
    pub model_signature: ::std::option::Option<::std::string::String>,
    /// <p>The output of a SageMaker Edge Manager deployable resource.</p>
    pub preset_deployment_output: ::std::option::Option<crate::types::EdgePresetDeploymentOutput>,
    _request_id: Option<String>,
}
impl DescribeEdgePackagingJobOutput {
    /// <p>The Amazon Resource Name (ARN) of the edge packaging job.</p>
    pub fn edge_packaging_job_arn(&self) -> ::std::option::Option<&str> {
        self.edge_packaging_job_arn.as_deref()
    }
    /// <p>The name of the edge packaging job.</p>
    pub fn edge_packaging_job_name(&self) -> ::std::option::Option<&str> {
        self.edge_packaging_job_name.as_deref()
    }
    /// <p>The name of the SageMaker Neo compilation job that is used to locate model artifacts that are being packaged.</p>
    pub fn compilation_job_name(&self) -> ::std::option::Option<&str> {
        self.compilation_job_name.as_deref()
    }
    /// <p>The name of the model.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
    /// <p>The version of the model.</p>
    pub fn model_version(&self) -> ::std::option::Option<&str> {
        self.model_version.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to download and upload the model, and to contact Neo.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The output configuration for the edge packaging job.</p>
    pub fn output_config(&self) -> ::std::option::Option<&crate::types::EdgeOutputConfig> {
        self.output_config.as_ref()
    }
    /// <p>The Amazon Web Services KMS key to use when encrypting the EBS volume the job run on.</p>
    pub fn resource_key(&self) -> ::std::option::Option<&str> {
        self.resource_key.as_deref()
    }
    /// <p>The current status of the packaging job.</p>
    pub fn edge_packaging_job_status(&self) -> ::std::option::Option<&crate::types::EdgePackagingJobStatus> {
        self.edge_packaging_job_status.as_ref()
    }
    /// <p>Returns a message describing the job status and error messages.</p>
    pub fn edge_packaging_job_status_message(&self) -> ::std::option::Option<&str> {
        self.edge_packaging_job_status_message.as_deref()
    }
    /// <p>The timestamp of when the packaging job was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The timestamp of when the job was last updated.</p>
    pub fn last_modified_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time.as_ref()
    }
    /// <p>The Amazon Simple Storage (S3) URI where model artifacts ares stored.</p>
    pub fn model_artifact(&self) -> ::std::option::Option<&str> {
        self.model_artifact.as_deref()
    }
    /// <p>The signature document of files in the model artifact.</p>
    pub fn model_signature(&self) -> ::std::option::Option<&str> {
        self.model_signature.as_deref()
    }
    /// <p>The output of a SageMaker Edge Manager deployable resource.</p>
    pub fn preset_deployment_output(&self) -> ::std::option::Option<&crate::types::EdgePresetDeploymentOutput> {
        self.preset_deployment_output.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEdgePackagingJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEdgePackagingJobOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEdgePackagingJobOutput`](crate::operation::describe_edge_packaging_job::DescribeEdgePackagingJobOutput).
    pub fn builder() -> crate::operation::describe_edge_packaging_job::builders::DescribeEdgePackagingJobOutputBuilder {
        crate::operation::describe_edge_packaging_job::builders::DescribeEdgePackagingJobOutputBuilder::default()
    }
}

/// A builder for [`DescribeEdgePackagingJobOutput`](crate::operation::describe_edge_packaging_job::DescribeEdgePackagingJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEdgePackagingJobOutputBuilder {
    pub(crate) edge_packaging_job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) edge_packaging_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) compilation_job_name: ::std::option::Option<::std::string::String>,
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
    pub(crate) model_version: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) output_config: ::std::option::Option<crate::types::EdgeOutputConfig>,
    pub(crate) resource_key: ::std::option::Option<::std::string::String>,
    pub(crate) edge_packaging_job_status: ::std::option::Option<crate::types::EdgePackagingJobStatus>,
    pub(crate) edge_packaging_job_status_message: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) model_artifact: ::std::option::Option<::std::string::String>,
    pub(crate) model_signature: ::std::option::Option<::std::string::String>,
    pub(crate) preset_deployment_output: ::std::option::Option<crate::types::EdgePresetDeploymentOutput>,
    _request_id: Option<String>,
}
impl DescribeEdgePackagingJobOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the edge packaging job.</p>
    /// This field is required.
    pub fn edge_packaging_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.edge_packaging_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the edge packaging job.</p>
    pub fn set_edge_packaging_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.edge_packaging_job_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the edge packaging job.</p>
    pub fn get_edge_packaging_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.edge_packaging_job_arn
    }
    /// <p>The name of the edge packaging job.</p>
    /// This field is required.
    pub fn edge_packaging_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.edge_packaging_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the edge packaging job.</p>
    pub fn set_edge_packaging_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.edge_packaging_job_name = input;
        self
    }
    /// <p>The name of the edge packaging job.</p>
    pub fn get_edge_packaging_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.edge_packaging_job_name
    }
    /// <p>The name of the SageMaker Neo compilation job that is used to locate model artifacts that are being packaged.</p>
    pub fn compilation_job_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.compilation_job_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the SageMaker Neo compilation job that is used to locate model artifacts that are being packaged.</p>
    pub fn set_compilation_job_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.compilation_job_name = input;
        self
    }
    /// <p>The name of the SageMaker Neo compilation job that is used to locate model artifacts that are being packaged.</p>
    pub fn get_compilation_job_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.compilation_job_name
    }
    /// <p>The name of the model.</p>
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the model.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the model.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// <p>The version of the model.</p>
    pub fn model_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the model.</p>
    pub fn set_model_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_version = input;
        self
    }
    /// <p>The version of the model.</p>
    pub fn get_model_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_version
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to download and upload the model, and to contact Neo.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to download and upload the model, and to contact Neo.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that enables Amazon SageMaker to download and upload the model, and to contact Neo.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The output configuration for the edge packaging job.</p>
    pub fn output_config(mut self, input: crate::types::EdgeOutputConfig) -> Self {
        self.output_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output configuration for the edge packaging job.</p>
    pub fn set_output_config(mut self, input: ::std::option::Option<crate::types::EdgeOutputConfig>) -> Self {
        self.output_config = input;
        self
    }
    /// <p>The output configuration for the edge packaging job.</p>
    pub fn get_output_config(&self) -> &::std::option::Option<crate::types::EdgeOutputConfig> {
        &self.output_config
    }
    /// <p>The Amazon Web Services KMS key to use when encrypting the EBS volume the job run on.</p>
    pub fn resource_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services KMS key to use when encrypting the EBS volume the job run on.</p>
    pub fn set_resource_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_key = input;
        self
    }
    /// <p>The Amazon Web Services KMS key to use when encrypting the EBS volume the job run on.</p>
    pub fn get_resource_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_key
    }
    /// <p>The current status of the packaging job.</p>
    /// This field is required.
    pub fn edge_packaging_job_status(mut self, input: crate::types::EdgePackagingJobStatus) -> Self {
        self.edge_packaging_job_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the packaging job.</p>
    pub fn set_edge_packaging_job_status(mut self, input: ::std::option::Option<crate::types::EdgePackagingJobStatus>) -> Self {
        self.edge_packaging_job_status = input;
        self
    }
    /// <p>The current status of the packaging job.</p>
    pub fn get_edge_packaging_job_status(&self) -> &::std::option::Option<crate::types::EdgePackagingJobStatus> {
        &self.edge_packaging_job_status
    }
    /// <p>Returns a message describing the job status and error messages.</p>
    pub fn edge_packaging_job_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.edge_packaging_job_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns a message describing the job status and error messages.</p>
    pub fn set_edge_packaging_job_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.edge_packaging_job_status_message = input;
        self
    }
    /// <p>Returns a message describing the job status and error messages.</p>
    pub fn get_edge_packaging_job_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.edge_packaging_job_status_message
    }
    /// <p>The timestamp of when the packaging job was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the packaging job was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The timestamp of when the packaging job was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The timestamp of when the job was last updated.</p>
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the job was last updated.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp of when the job was last updated.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>The Amazon Simple Storage (S3) URI where model artifacts ares stored.</p>
    pub fn model_artifact(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_artifact = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Simple Storage (S3) URI where model artifacts ares stored.</p>
    pub fn set_model_artifact(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_artifact = input;
        self
    }
    /// <p>The Amazon Simple Storage (S3) URI where model artifacts ares stored.</p>
    pub fn get_model_artifact(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_artifact
    }
    /// <p>The signature document of files in the model artifact.</p>
    pub fn model_signature(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_signature = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The signature document of files in the model artifact.</p>
    pub fn set_model_signature(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_signature = input;
        self
    }
    /// <p>The signature document of files in the model artifact.</p>
    pub fn get_model_signature(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_signature
    }
    /// <p>The output of a SageMaker Edge Manager deployable resource.</p>
    pub fn preset_deployment_output(mut self, input: crate::types::EdgePresetDeploymentOutput) -> Self {
        self.preset_deployment_output = ::std::option::Option::Some(input);
        self
    }
    /// <p>The output of a SageMaker Edge Manager deployable resource.</p>
    pub fn set_preset_deployment_output(mut self, input: ::std::option::Option<crate::types::EdgePresetDeploymentOutput>) -> Self {
        self.preset_deployment_output = input;
        self
    }
    /// <p>The output of a SageMaker Edge Manager deployable resource.</p>
    pub fn get_preset_deployment_output(&self) -> &::std::option::Option<crate::types::EdgePresetDeploymentOutput> {
        &self.preset_deployment_output
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEdgePackagingJobOutput`](crate::operation::describe_edge_packaging_job::DescribeEdgePackagingJobOutput).
    pub fn build(self) -> crate::operation::describe_edge_packaging_job::DescribeEdgePackagingJobOutput {
        crate::operation::describe_edge_packaging_job::DescribeEdgePackagingJobOutput {
            edge_packaging_job_arn: self.edge_packaging_job_arn,
            edge_packaging_job_name: self.edge_packaging_job_name,
            compilation_job_name: self.compilation_job_name,
            model_name: self.model_name,
            model_version: self.model_version,
            role_arn: self.role_arn,
            output_config: self.output_config,
            resource_key: self.resource_key,
            edge_packaging_job_status: self.edge_packaging_job_status,
            edge_packaging_job_status_message: self.edge_packaging_job_status_message,
            creation_time: self.creation_time,
            last_modified_time: self.last_modified_time,
            model_artifact: self.model_artifact,
            model_signature: self.model_signature,
            preset_deployment_output: self.preset_deployment_output,
            _request_id: self._request_id,
        }
    }
}
