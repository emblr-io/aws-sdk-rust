// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that contains details about the metadata for an Amazon ECR resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceScanMetadata {
    /// <p>An object that contains details about the repository an Amazon ECR image resides in.</p>
    pub ecr_repository: ::std::option::Option<crate::types::EcrRepositoryMetadata>,
    /// <p>An object that contains details about the container metadata for an Amazon ECR image.</p>
    pub ecr_image: ::std::option::Option<crate::types::EcrContainerImageMetadata>,
    /// <p>An object that contains metadata details for an Amazon EC2 instance.</p>
    pub ec2: ::std::option::Option<crate::types::Ec2Metadata>,
    /// <p>An object that contains metadata details for an Amazon Web Services Lambda function.</p>
    pub lambda_function: ::std::option::Option<crate::types::LambdaFunctionMetadata>,
    /// <p>Contains metadata about scan coverage for a code repository resource.</p>
    pub code_repository: ::std::option::Option<crate::types::CodeRepositoryMetadata>,
}
impl ResourceScanMetadata {
    /// <p>An object that contains details about the repository an Amazon ECR image resides in.</p>
    pub fn ecr_repository(&self) -> ::std::option::Option<&crate::types::EcrRepositoryMetadata> {
        self.ecr_repository.as_ref()
    }
    /// <p>An object that contains details about the container metadata for an Amazon ECR image.</p>
    pub fn ecr_image(&self) -> ::std::option::Option<&crate::types::EcrContainerImageMetadata> {
        self.ecr_image.as_ref()
    }
    /// <p>An object that contains metadata details for an Amazon EC2 instance.</p>
    pub fn ec2(&self) -> ::std::option::Option<&crate::types::Ec2Metadata> {
        self.ec2.as_ref()
    }
    /// <p>An object that contains metadata details for an Amazon Web Services Lambda function.</p>
    pub fn lambda_function(&self) -> ::std::option::Option<&crate::types::LambdaFunctionMetadata> {
        self.lambda_function.as_ref()
    }
    /// <p>Contains metadata about scan coverage for a code repository resource.</p>
    pub fn code_repository(&self) -> ::std::option::Option<&crate::types::CodeRepositoryMetadata> {
        self.code_repository.as_ref()
    }
}
impl ResourceScanMetadata {
    /// Creates a new builder-style object to manufacture [`ResourceScanMetadata`](crate::types::ResourceScanMetadata).
    pub fn builder() -> crate::types::builders::ResourceScanMetadataBuilder {
        crate::types::builders::ResourceScanMetadataBuilder::default()
    }
}

/// A builder for [`ResourceScanMetadata`](crate::types::ResourceScanMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceScanMetadataBuilder {
    pub(crate) ecr_repository: ::std::option::Option<crate::types::EcrRepositoryMetadata>,
    pub(crate) ecr_image: ::std::option::Option<crate::types::EcrContainerImageMetadata>,
    pub(crate) ec2: ::std::option::Option<crate::types::Ec2Metadata>,
    pub(crate) lambda_function: ::std::option::Option<crate::types::LambdaFunctionMetadata>,
    pub(crate) code_repository: ::std::option::Option<crate::types::CodeRepositoryMetadata>,
}
impl ResourceScanMetadataBuilder {
    /// <p>An object that contains details about the repository an Amazon ECR image resides in.</p>
    pub fn ecr_repository(mut self, input: crate::types::EcrRepositoryMetadata) -> Self {
        self.ecr_repository = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains details about the repository an Amazon ECR image resides in.</p>
    pub fn set_ecr_repository(mut self, input: ::std::option::Option<crate::types::EcrRepositoryMetadata>) -> Self {
        self.ecr_repository = input;
        self
    }
    /// <p>An object that contains details about the repository an Amazon ECR image resides in.</p>
    pub fn get_ecr_repository(&self) -> &::std::option::Option<crate::types::EcrRepositoryMetadata> {
        &self.ecr_repository
    }
    /// <p>An object that contains details about the container metadata for an Amazon ECR image.</p>
    pub fn ecr_image(mut self, input: crate::types::EcrContainerImageMetadata) -> Self {
        self.ecr_image = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains details about the container metadata for an Amazon ECR image.</p>
    pub fn set_ecr_image(mut self, input: ::std::option::Option<crate::types::EcrContainerImageMetadata>) -> Self {
        self.ecr_image = input;
        self
    }
    /// <p>An object that contains details about the container metadata for an Amazon ECR image.</p>
    pub fn get_ecr_image(&self) -> &::std::option::Option<crate::types::EcrContainerImageMetadata> {
        &self.ecr_image
    }
    /// <p>An object that contains metadata details for an Amazon EC2 instance.</p>
    pub fn ec2(mut self, input: crate::types::Ec2Metadata) -> Self {
        self.ec2 = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains metadata details for an Amazon EC2 instance.</p>
    pub fn set_ec2(mut self, input: ::std::option::Option<crate::types::Ec2Metadata>) -> Self {
        self.ec2 = input;
        self
    }
    /// <p>An object that contains metadata details for an Amazon EC2 instance.</p>
    pub fn get_ec2(&self) -> &::std::option::Option<crate::types::Ec2Metadata> {
        &self.ec2
    }
    /// <p>An object that contains metadata details for an Amazon Web Services Lambda function.</p>
    pub fn lambda_function(mut self, input: crate::types::LambdaFunctionMetadata) -> Self {
        self.lambda_function = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains metadata details for an Amazon Web Services Lambda function.</p>
    pub fn set_lambda_function(mut self, input: ::std::option::Option<crate::types::LambdaFunctionMetadata>) -> Self {
        self.lambda_function = input;
        self
    }
    /// <p>An object that contains metadata details for an Amazon Web Services Lambda function.</p>
    pub fn get_lambda_function(&self) -> &::std::option::Option<crate::types::LambdaFunctionMetadata> {
        &self.lambda_function
    }
    /// <p>Contains metadata about scan coverage for a code repository resource.</p>
    pub fn code_repository(mut self, input: crate::types::CodeRepositoryMetadata) -> Self {
        self.code_repository = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains metadata about scan coverage for a code repository resource.</p>
    pub fn set_code_repository(mut self, input: ::std::option::Option<crate::types::CodeRepositoryMetadata>) -> Self {
        self.code_repository = input;
        self
    }
    /// <p>Contains metadata about scan coverage for a code repository resource.</p>
    pub fn get_code_repository(&self) -> &::std::option::Option<crate::types::CodeRepositoryMetadata> {
        &self.code_repository
    }
    /// Consumes the builder and constructs a [`ResourceScanMetadata`](crate::types::ResourceScanMetadata).
    pub fn build(self) -> crate::types::ResourceScanMetadata {
        crate::types::ResourceScanMetadata {
            ecr_repository: self.ecr_repository,
            ecr_image: self.ecr_image,
            ec2: self.ec2,
            lambda_function: self.lambda_function,
            code_repository: self.code_repository,
        }
    }
}
