// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a database snapshot.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RelationalDatabaseSnapshot {
    /// <p>The name of the database snapshot.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the database snapshot.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The support code for the database snapshot. Include this code in your email to support when you have questions about a database snapshot in Lightsail. This code enables our support team to look up your Lightsail information more easily.</p>
    pub support_code: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp when the database snapshot was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Region name and Availability Zone where the database snapshot is located.</p>
    pub location: ::std::option::Option<crate::types::ResourceLocation>,
    /// <p>The Lightsail resource type.</p>
    pub resource_type: ::std::option::Option<crate::types::ResourceType>,
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The software of the database snapshot (for example, <code>MySQL</code>)</p>
    pub engine: ::std::option::Option<::std::string::String>,
    /// <p>The database engine version for the database snapshot (for example, <code>5.7.23</code>).</p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>The size of the disk in GB (for example, <code>32</code>) for the database snapshot.</p>
    pub size_in_gb: ::std::option::Option<i32>,
    /// <p>The state of the database snapshot.</p>
    pub state: ::std::option::Option<::std::string::String>,
    /// <p>The name of the source database from which the database snapshot was created.</p>
    pub from_relational_database_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the database from which the database snapshot was created.</p>
    pub from_relational_database_arn: ::std::option::Option<::std::string::String>,
    /// <p>The bundle ID of the database from which the database snapshot was created.</p>
    pub from_relational_database_bundle_id: ::std::option::Option<::std::string::String>,
    /// <p>The blueprint ID of the database from which the database snapshot was created. A blueprint describes the major engine version of a database.</p>
    pub from_relational_database_blueprint_id: ::std::option::Option<::std::string::String>,
}
impl RelationalDatabaseSnapshot {
    /// <p>The name of the database snapshot.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the database snapshot.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The support code for the database snapshot. Include this code in your email to support when you have questions about a database snapshot in Lightsail. This code enables our support team to look up your Lightsail information more easily.</p>
    pub fn support_code(&self) -> ::std::option::Option<&str> {
        self.support_code.as_deref()
    }
    /// <p>The timestamp when the database snapshot was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The Region name and Availability Zone where the database snapshot is located.</p>
    pub fn location(&self) -> ::std::option::Option<&crate::types::ResourceLocation> {
        self.location.as_ref()
    }
    /// <p>The Lightsail resource type.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The software of the database snapshot (for example, <code>MySQL</code>)</p>
    pub fn engine(&self) -> ::std::option::Option<&str> {
        self.engine.as_deref()
    }
    /// <p>The database engine version for the database snapshot (for example, <code>5.7.23</code>).</p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>The size of the disk in GB (for example, <code>32</code>) for the database snapshot.</p>
    pub fn size_in_gb(&self) -> ::std::option::Option<i32> {
        self.size_in_gb
    }
    /// <p>The state of the database snapshot.</p>
    pub fn state(&self) -> ::std::option::Option<&str> {
        self.state.as_deref()
    }
    /// <p>The name of the source database from which the database snapshot was created.</p>
    pub fn from_relational_database_name(&self) -> ::std::option::Option<&str> {
        self.from_relational_database_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the database from which the database snapshot was created.</p>
    pub fn from_relational_database_arn(&self) -> ::std::option::Option<&str> {
        self.from_relational_database_arn.as_deref()
    }
    /// <p>The bundle ID of the database from which the database snapshot was created.</p>
    pub fn from_relational_database_bundle_id(&self) -> ::std::option::Option<&str> {
        self.from_relational_database_bundle_id.as_deref()
    }
    /// <p>The blueprint ID of the database from which the database snapshot was created. A blueprint describes the major engine version of a database.</p>
    pub fn from_relational_database_blueprint_id(&self) -> ::std::option::Option<&str> {
        self.from_relational_database_blueprint_id.as_deref()
    }
}
impl RelationalDatabaseSnapshot {
    /// Creates a new builder-style object to manufacture [`RelationalDatabaseSnapshot`](crate::types::RelationalDatabaseSnapshot).
    pub fn builder() -> crate::types::builders::RelationalDatabaseSnapshotBuilder {
        crate::types::builders::RelationalDatabaseSnapshotBuilder::default()
    }
}

/// A builder for [`RelationalDatabaseSnapshot`](crate::types::RelationalDatabaseSnapshot).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RelationalDatabaseSnapshotBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) support_code: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) location: ::std::option::Option<crate::types::ResourceLocation>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) engine: ::std::option::Option<::std::string::String>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) size_in_gb: ::std::option::Option<i32>,
    pub(crate) state: ::std::option::Option<::std::string::String>,
    pub(crate) from_relational_database_name: ::std::option::Option<::std::string::String>,
    pub(crate) from_relational_database_arn: ::std::option::Option<::std::string::String>,
    pub(crate) from_relational_database_bundle_id: ::std::option::Option<::std::string::String>,
    pub(crate) from_relational_database_blueprint_id: ::std::option::Option<::std::string::String>,
}
impl RelationalDatabaseSnapshotBuilder {
    /// <p>The name of the database snapshot.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the database snapshot.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the database snapshot.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the database snapshot.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database snapshot.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database snapshot.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The support code for the database snapshot. Include this code in your email to support when you have questions about a database snapshot in Lightsail. This code enables our support team to look up your Lightsail information more easily.</p>
    pub fn support_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.support_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The support code for the database snapshot. Include this code in your email to support when you have questions about a database snapshot in Lightsail. This code enables our support team to look up your Lightsail information more easily.</p>
    pub fn set_support_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.support_code = input;
        self
    }
    /// <p>The support code for the database snapshot. Include this code in your email to support when you have questions about a database snapshot in Lightsail. This code enables our support team to look up your Lightsail information more easily.</p>
    pub fn get_support_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.support_code
    }
    /// <p>The timestamp when the database snapshot was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the database snapshot was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp when the database snapshot was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The Region name and Availability Zone where the database snapshot is located.</p>
    pub fn location(mut self, input: crate::types::ResourceLocation) -> Self {
        self.location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Region name and Availability Zone where the database snapshot is located.</p>
    pub fn set_location(mut self, input: ::std::option::Option<crate::types::ResourceLocation>) -> Self {
        self.location = input;
        self
    }
    /// <p>The Region name and Availability Zone where the database snapshot is located.</p>
    pub fn get_location(&self) -> &::std::option::Option<crate::types::ResourceLocation> {
        &self.location
    }
    /// <p>The Lightsail resource type.</p>
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Lightsail resource type.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The Lightsail resource type.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag keys and optional values for the resource. For more information about tags in Lightsail, see the <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-tags">Amazon Lightsail Developer Guide</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The software of the database snapshot (for example, <code>MySQL</code>)</p>
    pub fn engine(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The software of the database snapshot (for example, <code>MySQL</code>)</p>
    pub fn set_engine(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine = input;
        self
    }
    /// <p>The software of the database snapshot (for example, <code>MySQL</code>)</p>
    pub fn get_engine(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine
    }
    /// <p>The database engine version for the database snapshot (for example, <code>5.7.23</code>).</p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database engine version for the database snapshot (for example, <code>5.7.23</code>).</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The database engine version for the database snapshot (for example, <code>5.7.23</code>).</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>The size of the disk in GB (for example, <code>32</code>) for the database snapshot.</p>
    pub fn size_in_gb(mut self, input: i32) -> Self {
        self.size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size of the disk in GB (for example, <code>32</code>) for the database snapshot.</p>
    pub fn set_size_in_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_gb = input;
        self
    }
    /// <p>The size of the disk in GB (for example, <code>32</code>) for the database snapshot.</p>
    pub fn get_size_in_gb(&self) -> &::std::option::Option<i32> {
        &self.size_in_gb
    }
    /// <p>The state of the database snapshot.</p>
    pub fn state(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The state of the database snapshot.</p>
    pub fn set_state(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the database snapshot.</p>
    pub fn get_state(&self) -> &::std::option::Option<::std::string::String> {
        &self.state
    }
    /// <p>The name of the source database from which the database snapshot was created.</p>
    pub fn from_relational_database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_relational_database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the source database from which the database snapshot was created.</p>
    pub fn set_from_relational_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_relational_database_name = input;
        self
    }
    /// <p>The name of the source database from which the database snapshot was created.</p>
    pub fn get_from_relational_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_relational_database_name
    }
    /// <p>The Amazon Resource Name (ARN) of the database from which the database snapshot was created.</p>
    pub fn from_relational_database_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_relational_database_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database from which the database snapshot was created.</p>
    pub fn set_from_relational_database_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_relational_database_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the database from which the database snapshot was created.</p>
    pub fn get_from_relational_database_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_relational_database_arn
    }
    /// <p>The bundle ID of the database from which the database snapshot was created.</p>
    pub fn from_relational_database_bundle_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_relational_database_bundle_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The bundle ID of the database from which the database snapshot was created.</p>
    pub fn set_from_relational_database_bundle_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_relational_database_bundle_id = input;
        self
    }
    /// <p>The bundle ID of the database from which the database snapshot was created.</p>
    pub fn get_from_relational_database_bundle_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_relational_database_bundle_id
    }
    /// <p>The blueprint ID of the database from which the database snapshot was created. A blueprint describes the major engine version of a database.</p>
    pub fn from_relational_database_blueprint_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_relational_database_blueprint_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The blueprint ID of the database from which the database snapshot was created. A blueprint describes the major engine version of a database.</p>
    pub fn set_from_relational_database_blueprint_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_relational_database_blueprint_id = input;
        self
    }
    /// <p>The blueprint ID of the database from which the database snapshot was created. A blueprint describes the major engine version of a database.</p>
    pub fn get_from_relational_database_blueprint_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_relational_database_blueprint_id
    }
    /// Consumes the builder and constructs a [`RelationalDatabaseSnapshot`](crate::types::RelationalDatabaseSnapshot).
    pub fn build(self) -> crate::types::RelationalDatabaseSnapshot {
        crate::types::RelationalDatabaseSnapshot {
            name: self.name,
            arn: self.arn,
            support_code: self.support_code,
            created_at: self.created_at,
            location: self.location,
            resource_type: self.resource_type,
            tags: self.tags,
            engine: self.engine,
            engine_version: self.engine_version,
            size_in_gb: self.size_in_gb,
            state: self.state,
            from_relational_database_name: self.from_relational_database_name,
            from_relational_database_arn: self.from_relational_database_arn,
            from_relational_database_bundle_id: self.from_relational_database_bundle_id,
            from_relational_database_blueprint_id: self.from_relational_database_blueprint_id,
        }
    }
}
