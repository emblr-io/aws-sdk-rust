// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDbProxyEndpointInput {
    /// <p>The name of the DB proxy associated with the DB proxy endpoint that you create.</p>
    pub db_proxy_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the DB proxy endpoint to create.</p>
    pub db_proxy_endpoint_name: ::std::option::Option<::std::string::String>,
    /// <p>The VPC subnet IDs for the DB proxy endpoint that you create. You can specify a different set of subnet IDs than for the original DB proxy.</p>
    pub vpc_subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The VPC security group IDs for the DB proxy endpoint that you create. You can specify a different set of security group IDs than for the original DB proxy. The default is the default security group for the VPC.</p>
    pub vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The role of the DB proxy endpoint. The role determines whether the endpoint can be used for read/write or only read operations. The default is <code>READ_WRITE</code>. The only role that proxies for RDS for Microsoft SQL Server support is <code>READ_WRITE</code>.</p>
    pub target_role: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>,
    /// <p>A list of tags.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html">Tagging Amazon RDS resources</a> in the <i>Amazon RDS User Guide</i> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html">Tagging Amazon Aurora and Amazon RDS resources</a> in the <i>Amazon Aurora User Guide</i>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateDbProxyEndpointInput {
    /// <p>The name of the DB proxy associated with the DB proxy endpoint that you create.</p>
    pub fn db_proxy_name(&self) -> ::std::option::Option<&str> {
        self.db_proxy_name.as_deref()
    }
    /// <p>The name of the DB proxy endpoint to create.</p>
    pub fn db_proxy_endpoint_name(&self) -> ::std::option::Option<&str> {
        self.db_proxy_endpoint_name.as_deref()
    }
    /// <p>The VPC subnet IDs for the DB proxy endpoint that you create. You can specify a different set of subnet IDs than for the original DB proxy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_subnet_ids.is_none()`.
    pub fn vpc_subnet_ids(&self) -> &[::std::string::String] {
        self.vpc_subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The VPC security group IDs for the DB proxy endpoint that you create. You can specify a different set of security group IDs than for the original DB proxy. The default is the default security group for the VPC.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_security_group_ids.is_none()`.
    pub fn vpc_security_group_ids(&self) -> &[::std::string::String] {
        self.vpc_security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The role of the DB proxy endpoint. The role determines whether the endpoint can be used for read/write or only read operations. The default is <code>READ_WRITE</code>. The only role that proxies for RDS for Microsoft SQL Server support is <code>READ_WRITE</code>.</p>
    pub fn target_role(&self) -> ::std::option::Option<&crate::types::DbProxyEndpointTargetRole> {
        self.target_role.as_ref()
    }
    /// <p>A list of tags.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html">Tagging Amazon RDS resources</a> in the <i>Amazon RDS User Guide</i> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html">Tagging Amazon Aurora and Amazon RDS resources</a> in the <i>Amazon Aurora User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateDbProxyEndpointInput {
    /// Creates a new builder-style object to manufacture [`CreateDbProxyEndpointInput`](crate::operation::create_db_proxy_endpoint::CreateDbProxyEndpointInput).
    pub fn builder() -> crate::operation::create_db_proxy_endpoint::builders::CreateDbProxyEndpointInputBuilder {
        crate::operation::create_db_proxy_endpoint::builders::CreateDbProxyEndpointInputBuilder::default()
    }
}

/// A builder for [`CreateDbProxyEndpointInput`](crate::operation::create_db_proxy_endpoint::CreateDbProxyEndpointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDbProxyEndpointInputBuilder {
    pub(crate) db_proxy_name: ::std::option::Option<::std::string::String>,
    pub(crate) db_proxy_endpoint_name: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) vpc_security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) target_role: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateDbProxyEndpointInputBuilder {
    /// <p>The name of the DB proxy associated with the DB proxy endpoint that you create.</p>
    /// This field is required.
    pub fn db_proxy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB proxy associated with the DB proxy endpoint that you create.</p>
    pub fn set_db_proxy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_name = input;
        self
    }
    /// <p>The name of the DB proxy associated with the DB proxy endpoint that you create.</p>
    pub fn get_db_proxy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_name
    }
    /// <p>The name of the DB proxy endpoint to create.</p>
    /// This field is required.
    pub fn db_proxy_endpoint_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_proxy_endpoint_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB proxy endpoint to create.</p>
    pub fn set_db_proxy_endpoint_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_proxy_endpoint_name = input;
        self
    }
    /// <p>The name of the DB proxy endpoint to create.</p>
    pub fn get_db_proxy_endpoint_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_proxy_endpoint_name
    }
    /// Appends an item to `vpc_subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_subnet_ids`](Self::set_vpc_subnet_ids).
    ///
    /// <p>The VPC subnet IDs for the DB proxy endpoint that you create. You can specify a different set of subnet IDs than for the original DB proxy.</p>
    pub fn vpc_subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPC subnet IDs for the DB proxy endpoint that you create. You can specify a different set of subnet IDs than for the original DB proxy.</p>
    pub fn set_vpc_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_subnet_ids = input;
        self
    }
    /// <p>The VPC subnet IDs for the DB proxy endpoint that you create. You can specify a different set of subnet IDs than for the original DB proxy.</p>
    pub fn get_vpc_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_subnet_ids
    }
    /// Appends an item to `vpc_security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_vpc_security_group_ids`](Self::set_vpc_security_group_ids).
    ///
    /// <p>The VPC security group IDs for the DB proxy endpoint that you create. You can specify a different set of security group IDs than for the original DB proxy. The default is the default security group for the VPC.</p>
    pub fn vpc_security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.vpc_security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.vpc_security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPC security group IDs for the DB proxy endpoint that you create. You can specify a different set of security group IDs than for the original DB proxy. The default is the default security group for the VPC.</p>
    pub fn set_vpc_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.vpc_security_group_ids = input;
        self
    }
    /// <p>The VPC security group IDs for the DB proxy endpoint that you create. You can specify a different set of security group IDs than for the original DB proxy. The default is the default security group for the VPC.</p>
    pub fn get_vpc_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.vpc_security_group_ids
    }
    /// <p>The role of the DB proxy endpoint. The role determines whether the endpoint can be used for read/write or only read operations. The default is <code>READ_WRITE</code>. The only role that proxies for RDS for Microsoft SQL Server support is <code>READ_WRITE</code>.</p>
    pub fn target_role(mut self, input: crate::types::DbProxyEndpointTargetRole) -> Self {
        self.target_role = ::std::option::Option::Some(input);
        self
    }
    /// <p>The role of the DB proxy endpoint. The role determines whether the endpoint can be used for read/write or only read operations. The default is <code>READ_WRITE</code>. The only role that proxies for RDS for Microsoft SQL Server support is <code>READ_WRITE</code>.</p>
    pub fn set_target_role(mut self, input: ::std::option::Option<crate::types::DbProxyEndpointTargetRole>) -> Self {
        self.target_role = input;
        self
    }
    /// <p>The role of the DB proxy endpoint. The role determines whether the endpoint can be used for read/write or only read operations. The default is <code>READ_WRITE</code>. The only role that proxies for RDS for Microsoft SQL Server support is <code>READ_WRITE</code>.</p>
    pub fn get_target_role(&self) -> &::std::option::Option<crate::types::DbProxyEndpointTargetRole> {
        &self.target_role
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html">Tagging Amazon RDS resources</a> in the <i>Amazon RDS User Guide</i> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html">Tagging Amazon Aurora and Amazon RDS resources</a> in the <i>Amazon Aurora User Guide</i>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html">Tagging Amazon RDS resources</a> in the <i>Amazon RDS User Guide</i> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html">Tagging Amazon Aurora and Amazon RDS resources</a> in the <i>Amazon Aurora User Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html">Tagging Amazon RDS resources</a> in the <i>Amazon RDS User Guide</i> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_Tagging.html">Tagging Amazon Aurora and Amazon RDS resources</a> in the <i>Amazon Aurora User Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateDbProxyEndpointInput`](crate::operation::create_db_proxy_endpoint::CreateDbProxyEndpointInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_db_proxy_endpoint::CreateDbProxyEndpointInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_db_proxy_endpoint::CreateDbProxyEndpointInput {
            db_proxy_name: self.db_proxy_name,
            db_proxy_endpoint_name: self.db_proxy_endpoint_name,
            vpc_subnet_ids: self.vpc_subnet_ids,
            vpc_security_group_ids: self.vpc_security_group_ids,
            target_role: self.target_role,
            tags: self.tags,
        })
    }
}
