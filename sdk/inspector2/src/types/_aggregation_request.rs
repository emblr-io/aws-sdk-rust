// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about an aggregation request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub enum AggregationRequest {
    /// <p>An object that contains details about an aggregation request based on Amazon Web Services account IDs.</p>
    AccountAggregation(crate::types::AccountAggregation),
    /// <p>An object that contains details about an aggregation request based on Amazon Machine Images (AMIs).</p>
    AmiAggregation(crate::types::AmiAggregation),
    /// <p>An object that contains details about an aggregation request based on Amazon ECR container images.</p>
    AwsEcrContainerAggregation(crate::types::AwsEcrContainerAggregation),
    /// <p>An object that contains details about an aggregation request based on code repositories.</p>
    CodeRepositoryAggregation(crate::types::CodeRepositoryAggregation),
    /// <p>An object that contains details about an aggregation request based on Amazon EC2 instances.</p>
    Ec2InstanceAggregation(crate::types::Ec2InstanceAggregation),
    /// <p>An object that contains details about an aggregation request based on finding types.</p>
    FindingTypeAggregation(crate::types::FindingTypeAggregation),
    /// <p>An object that contains details about an aggregation request based on container image layers.</p>
    ImageLayerAggregation(crate::types::ImageLayerAggregation),
    /// <p>Returns an object with findings aggregated by Amazon Web Services Lambda function.</p>
    LambdaFunctionAggregation(crate::types::LambdaFunctionAggregation),
    /// <p>Returns an object with findings aggregated by Amazon Web Services Lambda layer.</p>
    LambdaLayerAggregation(crate::types::LambdaLayerAggregation),
    /// <p>An object that contains details about an aggregation request based on operating system package type.</p>
    PackageAggregation(crate::types::PackageAggregation),
    /// <p>An object that contains details about an aggregation request based on Amazon ECR repositories.</p>
    RepositoryAggregation(crate::types::RepositoryAggregation),
    /// <p>An object that contains details about an aggregation request based on finding title.</p>
    TitleAggregation(crate::types::TitleAggregation),
    /// The `Unknown` variant represents cases where new union variant was received. Consider upgrading the SDK to the latest available version.
    /// An unknown enum variant
    ///
    /// _Note: If you encounter this error, consider upgrading your SDK to the latest version._
    /// The `Unknown` variant represents cases where the server sent a value that wasn't recognized
    /// by the client. This can happen when the server adds new functionality, but the client has not been updated.
    /// To investigate this, consider turning on debug logging to print the raw HTTP response.
    #[non_exhaustive]
    Unknown,
}
impl AggregationRequest {
    /// Tries to convert the enum instance into [`AccountAggregation`](crate::types::AggregationRequest::AccountAggregation), extracting the inner [`AccountAggregation`](crate::types::AccountAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_account_aggregation(&self) -> ::std::result::Result<&crate::types::AccountAggregation, &Self> {
        if let AggregationRequest::AccountAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AccountAggregation`](crate::types::AggregationRequest::AccountAggregation).
    pub fn is_account_aggregation(&self) -> bool {
        self.as_account_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`AmiAggregation`](crate::types::AggregationRequest::AmiAggregation), extracting the inner [`AmiAggregation`](crate::types::AmiAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_ami_aggregation(&self) -> ::std::result::Result<&crate::types::AmiAggregation, &Self> {
        if let AggregationRequest::AmiAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AmiAggregation`](crate::types::AggregationRequest::AmiAggregation).
    pub fn is_ami_aggregation(&self) -> bool {
        self.as_ami_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`AwsEcrContainerAggregation`](crate::types::AggregationRequest::AwsEcrContainerAggregation), extracting the inner [`AwsEcrContainerAggregation`](crate::types::AwsEcrContainerAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_aws_ecr_container_aggregation(&self) -> ::std::result::Result<&crate::types::AwsEcrContainerAggregation, &Self> {
        if let AggregationRequest::AwsEcrContainerAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`AwsEcrContainerAggregation`](crate::types::AggregationRequest::AwsEcrContainerAggregation).
    pub fn is_aws_ecr_container_aggregation(&self) -> bool {
        self.as_aws_ecr_container_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`CodeRepositoryAggregation`](crate::types::AggregationRequest::CodeRepositoryAggregation), extracting the inner [`CodeRepositoryAggregation`](crate::types::CodeRepositoryAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_code_repository_aggregation(&self) -> ::std::result::Result<&crate::types::CodeRepositoryAggregation, &Self> {
        if let AggregationRequest::CodeRepositoryAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`CodeRepositoryAggregation`](crate::types::AggregationRequest::CodeRepositoryAggregation).
    pub fn is_code_repository_aggregation(&self) -> bool {
        self.as_code_repository_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`Ec2InstanceAggregation`](crate::types::AggregationRequest::Ec2InstanceAggregation), extracting the inner [`Ec2InstanceAggregation`](crate::types::Ec2InstanceAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_ec2_instance_aggregation(&self) -> ::std::result::Result<&crate::types::Ec2InstanceAggregation, &Self> {
        if let AggregationRequest::Ec2InstanceAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Ec2InstanceAggregation`](crate::types::AggregationRequest::Ec2InstanceAggregation).
    pub fn is_ec2_instance_aggregation(&self) -> bool {
        self.as_ec2_instance_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`FindingTypeAggregation`](crate::types::AggregationRequest::FindingTypeAggregation), extracting the inner [`FindingTypeAggregation`](crate::types::FindingTypeAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_finding_type_aggregation(&self) -> ::std::result::Result<&crate::types::FindingTypeAggregation, &Self> {
        if let AggregationRequest::FindingTypeAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`FindingTypeAggregation`](crate::types::AggregationRequest::FindingTypeAggregation).
    pub fn is_finding_type_aggregation(&self) -> bool {
        self.as_finding_type_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`ImageLayerAggregation`](crate::types::AggregationRequest::ImageLayerAggregation), extracting the inner [`ImageLayerAggregation`](crate::types::ImageLayerAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_image_layer_aggregation(&self) -> ::std::result::Result<&crate::types::ImageLayerAggregation, &Self> {
        if let AggregationRequest::ImageLayerAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`ImageLayerAggregation`](crate::types::AggregationRequest::ImageLayerAggregation).
    pub fn is_image_layer_aggregation(&self) -> bool {
        self.as_image_layer_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`LambdaFunctionAggregation`](crate::types::AggregationRequest::LambdaFunctionAggregation), extracting the inner [`LambdaFunctionAggregation`](crate::types::LambdaFunctionAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_lambda_function_aggregation(&self) -> ::std::result::Result<&crate::types::LambdaFunctionAggregation, &Self> {
        if let AggregationRequest::LambdaFunctionAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LambdaFunctionAggregation`](crate::types::AggregationRequest::LambdaFunctionAggregation).
    pub fn is_lambda_function_aggregation(&self) -> bool {
        self.as_lambda_function_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`LambdaLayerAggregation`](crate::types::AggregationRequest::LambdaLayerAggregation), extracting the inner [`LambdaLayerAggregation`](crate::types::LambdaLayerAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_lambda_layer_aggregation(&self) -> ::std::result::Result<&crate::types::LambdaLayerAggregation, &Self> {
        if let AggregationRequest::LambdaLayerAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`LambdaLayerAggregation`](crate::types::AggregationRequest::LambdaLayerAggregation).
    pub fn is_lambda_layer_aggregation(&self) -> bool {
        self.as_lambda_layer_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`PackageAggregation`](crate::types::AggregationRequest::PackageAggregation), extracting the inner [`PackageAggregation`](crate::types::PackageAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_package_aggregation(&self) -> ::std::result::Result<&crate::types::PackageAggregation, &Self> {
        if let AggregationRequest::PackageAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`PackageAggregation`](crate::types::AggregationRequest::PackageAggregation).
    pub fn is_package_aggregation(&self) -> bool {
        self.as_package_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`RepositoryAggregation`](crate::types::AggregationRequest::RepositoryAggregation), extracting the inner [`RepositoryAggregation`](crate::types::RepositoryAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_repository_aggregation(&self) -> ::std::result::Result<&crate::types::RepositoryAggregation, &Self> {
        if let AggregationRequest::RepositoryAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`RepositoryAggregation`](crate::types::AggregationRequest::RepositoryAggregation).
    pub fn is_repository_aggregation(&self) -> bool {
        self.as_repository_aggregation().is_ok()
    }
    /// Tries to convert the enum instance into [`TitleAggregation`](crate::types::AggregationRequest::TitleAggregation), extracting the inner [`TitleAggregation`](crate::types::TitleAggregation).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_title_aggregation(&self) -> ::std::result::Result<&crate::types::TitleAggregation, &Self> {
        if let AggregationRequest::TitleAggregation(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`TitleAggregation`](crate::types::AggregationRequest::TitleAggregation).
    pub fn is_title_aggregation(&self) -> bool {
        self.as_title_aggregation().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
