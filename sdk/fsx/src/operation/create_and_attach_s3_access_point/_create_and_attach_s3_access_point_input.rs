// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAndAttachS3AccessPointInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The name you want to assign to this S3 access point.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of S3 access point you want to create. Only <code>OpenZFS</code> is supported.</p>
    pub r#type: ::std::option::Option<crate::types::S3AccessPointAttachmentType>,
    /// <p>Specifies the configuration to use when creating and attaching an S3 access point to an FSx for OpenZFS volume.</p>
    pub open_zfs_configuration: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration>,
    /// <p>Specifies the virtual private cloud (VPC) configuration if you're creating an access point that is restricted to a VPC. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/access-points-vpc.html">Creating access points restricted to a virtual private cloud</a>.</p>
    pub s3_access_point: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointS3Configuration>,
}
impl CreateAndAttachS3AccessPointInput {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The name you want to assign to this S3 access point.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of S3 access point you want to create. Only <code>OpenZFS</code> is supported.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::S3AccessPointAttachmentType> {
        self.r#type.as_ref()
    }
    /// <p>Specifies the configuration to use when creating and attaching an S3 access point to an FSx for OpenZFS volume.</p>
    pub fn open_zfs_configuration(&self) -> ::std::option::Option<&crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration> {
        self.open_zfs_configuration.as_ref()
    }
    /// <p>Specifies the virtual private cloud (VPC) configuration if you're creating an access point that is restricted to a VPC. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/access-points-vpc.html">Creating access points restricted to a virtual private cloud</a>.</p>
    pub fn s3_access_point(&self) -> ::std::option::Option<&crate::types::CreateAndAttachS3AccessPointS3Configuration> {
        self.s3_access_point.as_ref()
    }
}
impl CreateAndAttachS3AccessPointInput {
    /// Creates a new builder-style object to manufacture [`CreateAndAttachS3AccessPointInput`](crate::operation::create_and_attach_s3_access_point::CreateAndAttachS3AccessPointInput).
    pub fn builder() -> crate::operation::create_and_attach_s3_access_point::builders::CreateAndAttachS3AccessPointInputBuilder {
        crate::operation::create_and_attach_s3_access_point::builders::CreateAndAttachS3AccessPointInputBuilder::default()
    }
}

/// A builder for [`CreateAndAttachS3AccessPointInput`](crate::operation::create_and_attach_s3_access_point::CreateAndAttachS3AccessPointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAndAttachS3AccessPointInputBuilder {
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::S3AccessPointAttachmentType>,
    pub(crate) open_zfs_configuration: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration>,
    pub(crate) s3_access_point: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointS3Configuration>,
}
impl CreateAndAttachS3AccessPointInputBuilder {
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>(Optional) An idempotency token for resource creation, in a string of up to 63 ASCII characters. This token is automatically filled on your behalf when you use the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The name you want to assign to this S3 access point.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name you want to assign to this S3 access point.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name you want to assign to this S3 access point.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of S3 access point you want to create. Only <code>OpenZFS</code> is supported.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::S3AccessPointAttachmentType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of S3 access point you want to create. Only <code>OpenZFS</code> is supported.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::S3AccessPointAttachmentType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of S3 access point you want to create. Only <code>OpenZFS</code> is supported.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::S3AccessPointAttachmentType> {
        &self.r#type
    }
    /// <p>Specifies the configuration to use when creating and attaching an S3 access point to an FSx for OpenZFS volume.</p>
    pub fn open_zfs_configuration(mut self, input: crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration) -> Self {
        self.open_zfs_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configuration to use when creating and attaching an S3 access point to an FSx for OpenZFS volume.</p>
    pub fn set_open_zfs_configuration(
        mut self,
        input: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration>,
    ) -> Self {
        self.open_zfs_configuration = input;
        self
    }
    /// <p>Specifies the configuration to use when creating and attaching an S3 access point to an FSx for OpenZFS volume.</p>
    pub fn get_open_zfs_configuration(&self) -> &::std::option::Option<crate::types::CreateAndAttachS3AccessPointOpenZfsConfiguration> {
        &self.open_zfs_configuration
    }
    /// <p>Specifies the virtual private cloud (VPC) configuration if you're creating an access point that is restricted to a VPC. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/access-points-vpc.html">Creating access points restricted to a virtual private cloud</a>.</p>
    pub fn s3_access_point(mut self, input: crate::types::CreateAndAttachS3AccessPointS3Configuration) -> Self {
        self.s3_access_point = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the virtual private cloud (VPC) configuration if you're creating an access point that is restricted to a VPC. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/access-points-vpc.html">Creating access points restricted to a virtual private cloud</a>.</p>
    pub fn set_s3_access_point(mut self, input: ::std::option::Option<crate::types::CreateAndAttachS3AccessPointS3Configuration>) -> Self {
        self.s3_access_point = input;
        self
    }
    /// <p>Specifies the virtual private cloud (VPC) configuration if you're creating an access point that is restricted to a VPC. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/OpenZFSGuide/access-points-vpc.html">Creating access points restricted to a virtual private cloud</a>.</p>
    pub fn get_s3_access_point(&self) -> &::std::option::Option<crate::types::CreateAndAttachS3AccessPointS3Configuration> {
        &self.s3_access_point
    }
    /// Consumes the builder and constructs a [`CreateAndAttachS3AccessPointInput`](crate::operation::create_and_attach_s3_access_point::CreateAndAttachS3AccessPointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_and_attach_s3_access_point::CreateAndAttachS3AccessPointInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_and_attach_s3_access_point::CreateAndAttachS3AccessPointInput {
            client_request_token: self.client_request_token,
            name: self.name,
            r#type: self.r#type,
            open_zfs_configuration: self.open_zfs_configuration,
            s3_access_point: self.s3_access_point,
        })
    }
}
