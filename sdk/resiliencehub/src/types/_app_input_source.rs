// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The list of Resilience Hub application input sources.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppInputSource {
    /// <p>The name of the input source.</p>
    pub source_name: ::std::option::Option<::std::string::String>,
    /// <p>The resource type of the input source.</p>
    pub import_type: crate::types::ResourceMappingType,
    /// <p>The Amazon Resource Name (ARN) of the input source. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub source_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Terraform s3 state ﬁle.</p>
    pub terraform_source: ::std::option::Option<crate::types::TerraformSource>,
    /// <p>The number of resources.</p>
    pub resource_count: i32,
    /// <p>The namespace on your Amazon Elastic Kubernetes Service cluster.</p>
    pub eks_source_cluster_namespace: ::std::option::Option<crate::types::EksSourceClusterNamespace>,
}
impl AppInputSource {
    /// <p>The name of the input source.</p>
    pub fn source_name(&self) -> ::std::option::Option<&str> {
        self.source_name.as_deref()
    }
    /// <p>The resource type of the input source.</p>
    pub fn import_type(&self) -> &crate::types::ResourceMappingType {
        &self.import_type
    }
    /// <p>The Amazon Resource Name (ARN) of the input source. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn source_arn(&self) -> ::std::option::Option<&str> {
        self.source_arn.as_deref()
    }
    /// <p>The name of the Terraform s3 state ﬁle.</p>
    pub fn terraform_source(&self) -> ::std::option::Option<&crate::types::TerraformSource> {
        self.terraform_source.as_ref()
    }
    /// <p>The number of resources.</p>
    pub fn resource_count(&self) -> i32 {
        self.resource_count
    }
    /// <p>The namespace on your Amazon Elastic Kubernetes Service cluster.</p>
    pub fn eks_source_cluster_namespace(&self) -> ::std::option::Option<&crate::types::EksSourceClusterNamespace> {
        self.eks_source_cluster_namespace.as_ref()
    }
}
impl AppInputSource {
    /// Creates a new builder-style object to manufacture [`AppInputSource`](crate::types::AppInputSource).
    pub fn builder() -> crate::types::builders::AppInputSourceBuilder {
        crate::types::builders::AppInputSourceBuilder::default()
    }
}

/// A builder for [`AppInputSource`](crate::types::AppInputSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppInputSourceBuilder {
    pub(crate) source_name: ::std::option::Option<::std::string::String>,
    pub(crate) import_type: ::std::option::Option<crate::types::ResourceMappingType>,
    pub(crate) source_arn: ::std::option::Option<::std::string::String>,
    pub(crate) terraform_source: ::std::option::Option<crate::types::TerraformSource>,
    pub(crate) resource_count: ::std::option::Option<i32>,
    pub(crate) eks_source_cluster_namespace: ::std::option::Option<crate::types::EksSourceClusterNamespace>,
}
impl AppInputSourceBuilder {
    /// <p>The name of the input source.</p>
    pub fn source_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the input source.</p>
    pub fn set_source_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_name = input;
        self
    }
    /// <p>The name of the input source.</p>
    pub fn get_source_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_name
    }
    /// <p>The resource type of the input source.</p>
    /// This field is required.
    pub fn import_type(mut self, input: crate::types::ResourceMappingType) -> Self {
        self.import_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type of the input source.</p>
    pub fn set_import_type(mut self, input: ::std::option::Option<crate::types::ResourceMappingType>) -> Self {
        self.import_type = input;
        self
    }
    /// <p>The resource type of the input source.</p>
    pub fn get_import_type(&self) -> &::std::option::Option<crate::types::ResourceMappingType> {
        &self.import_type
    }
    /// <p>The Amazon Resource Name (ARN) of the input source. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn source_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the input source. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_source_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the input source. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_source_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_arn
    }
    /// <p>The name of the Terraform s3 state ﬁle.</p>
    pub fn terraform_source(mut self, input: crate::types::TerraformSource) -> Self {
        self.terraform_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of the Terraform s3 state ﬁle.</p>
    pub fn set_terraform_source(mut self, input: ::std::option::Option<crate::types::TerraformSource>) -> Self {
        self.terraform_source = input;
        self
    }
    /// <p>The name of the Terraform s3 state ﬁle.</p>
    pub fn get_terraform_source(&self) -> &::std::option::Option<crate::types::TerraformSource> {
        &self.terraform_source
    }
    /// <p>The number of resources.</p>
    pub fn resource_count(mut self, input: i32) -> Self {
        self.resource_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of resources.</p>
    pub fn set_resource_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.resource_count = input;
        self
    }
    /// <p>The number of resources.</p>
    pub fn get_resource_count(&self) -> &::std::option::Option<i32> {
        &self.resource_count
    }
    /// <p>The namespace on your Amazon Elastic Kubernetes Service cluster.</p>
    pub fn eks_source_cluster_namespace(mut self, input: crate::types::EksSourceClusterNamespace) -> Self {
        self.eks_source_cluster_namespace = ::std::option::Option::Some(input);
        self
    }
    /// <p>The namespace on your Amazon Elastic Kubernetes Service cluster.</p>
    pub fn set_eks_source_cluster_namespace(mut self, input: ::std::option::Option<crate::types::EksSourceClusterNamespace>) -> Self {
        self.eks_source_cluster_namespace = input;
        self
    }
    /// <p>The namespace on your Amazon Elastic Kubernetes Service cluster.</p>
    pub fn get_eks_source_cluster_namespace(&self) -> &::std::option::Option<crate::types::EksSourceClusterNamespace> {
        &self.eks_source_cluster_namespace
    }
    /// Consumes the builder and constructs a [`AppInputSource`](crate::types::AppInputSource).
    /// This method will fail if any of the following fields are not set:
    /// - [`import_type`](crate::types::builders::AppInputSourceBuilder::import_type)
    pub fn build(self) -> ::std::result::Result<crate::types::AppInputSource, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AppInputSource {
            source_name: self.source_name,
            import_type: self.import_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "import_type",
                    "import_type was not specified but it is required when building AppInputSource",
                )
            })?,
            source_arn: self.source_arn,
            terraform_source: self.terraform_source,
            resource_count: self.resource_count.unwrap_or_default(),
            eks_source_cluster_namespace: self.eks_source_cluster_namespace,
        })
    }
}
