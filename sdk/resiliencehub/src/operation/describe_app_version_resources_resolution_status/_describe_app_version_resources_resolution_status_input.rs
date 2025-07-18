// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeAppVersionResourcesResolutionStatusInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub app_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version of the application.</p>
    pub app_version: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for a specific resolution.</p>
    pub resolution_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAppVersionResourcesResolutionStatusInput {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn app_arn(&self) -> ::std::option::Option<&str> {
        self.app_arn.as_deref()
    }
    /// <p>The version of the application.</p>
    pub fn app_version(&self) -> ::std::option::Option<&str> {
        self.app_version.as_deref()
    }
    /// <p>The identifier for a specific resolution.</p>
    pub fn resolution_id(&self) -> ::std::option::Option<&str> {
        self.resolution_id.as_deref()
    }
}
impl DescribeAppVersionResourcesResolutionStatusInput {
    /// Creates a new builder-style object to manufacture [`DescribeAppVersionResourcesResolutionStatusInput`](crate::operation::describe_app_version_resources_resolution_status::DescribeAppVersionResourcesResolutionStatusInput).
    pub fn builder(
    ) -> crate::operation::describe_app_version_resources_resolution_status::builders::DescribeAppVersionResourcesResolutionStatusInputBuilder {
        crate::operation::describe_app_version_resources_resolution_status::builders::DescribeAppVersionResourcesResolutionStatusInputBuilder::default(
        )
    }
}

/// A builder for [`DescribeAppVersionResourcesResolutionStatusInput`](crate::operation::describe_app_version_resources_resolution_status::DescribeAppVersionResourcesResolutionStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeAppVersionResourcesResolutionStatusInputBuilder {
    pub(crate) app_arn: ::std::option::Option<::std::string::String>,
    pub(crate) app_version: ::std::option::Option<::std::string::String>,
    pub(crate) resolution_id: ::std::option::Option<::std::string::String>,
}
impl DescribeAppVersionResourcesResolutionStatusInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    /// This field is required.
    pub fn app_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn set_app_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the Resilience Hub application. The format for this ARN is: arn:<code>partition</code>:resiliencehub:<code>region</code>:<code>account</code>:app/<code>app-id</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"> Amazon Resource Names (ARNs)</a> in the <i>Amazon Web Services General Reference</i> guide.</p>
    pub fn get_app_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_arn
    }
    /// <p>The version of the application.</p>
    /// This field is required.
    pub fn app_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the application.</p>
    pub fn set_app_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_version = input;
        self
    }
    /// <p>The version of the application.</p>
    pub fn get_app_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_version
    }
    /// <p>The identifier for a specific resolution.</p>
    pub fn resolution_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resolution_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for a specific resolution.</p>
    pub fn set_resolution_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resolution_id = input;
        self
    }
    /// <p>The identifier for a specific resolution.</p>
    pub fn get_resolution_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resolution_id
    }
    /// Consumes the builder and constructs a [`DescribeAppVersionResourcesResolutionStatusInput`](crate::operation::describe_app_version_resources_resolution_status::DescribeAppVersionResourcesResolutionStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_app_version_resources_resolution_status::DescribeAppVersionResourcesResolutionStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::describe_app_version_resources_resolution_status::DescribeAppVersionResourcesResolutionStatusInput {
                app_arn: self.app_arn,
                app_version: self.app_version,
                resolution_id: self.resolution_id,
            },
        )
    }
}
