// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about the limitations of target Amazon Web Services engines.</p>
/// <p>Your source database might include features that the target Amazon Web Services engine doesn't support. Fleet Advisor lists these features as limitations. You should consider these limitations during database migration. For each limitation, Fleet Advisor recommends an action that you can take to address or avoid this limitation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Limitation {
    /// <p>The identifier of the source database.</p>
    pub database_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the target engine that Fleet Advisor should use in the target engine recommendation. Valid values include <code>"rds-aurora-mysql"</code>, <code>"rds-aurora-postgresql"</code>, <code>"rds-mysql"</code>, <code>"rds-oracle"</code>, <code>"rds-sql-server"</code>, and <code>"rds-postgresql"</code>.</p>
    pub engine_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the limitation. Describes unsupported database features, migration action items, and other limitations.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the limitation. Provides additional information about the limitation, and includes recommended actions that you can take to address or avoid this limitation.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The impact of the limitation. You can use this parameter to prioritize limitations that you want to address. Valid values include <code>"Blocker"</code>, <code>"High"</code>, <code>"Medium"</code>, and <code>"Low"</code>.</p>
    pub impact: ::std::option::Option<::std::string::String>,
    /// <p>The type of the limitation, such as action required, upgrade required, and limited feature.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
}
impl Limitation {
    /// <p>The identifier of the source database.</p>
    pub fn database_id(&self) -> ::std::option::Option<&str> {
        self.database_id.as_deref()
    }
    /// <p>The name of the target engine that Fleet Advisor should use in the target engine recommendation. Valid values include <code>"rds-aurora-mysql"</code>, <code>"rds-aurora-postgresql"</code>, <code>"rds-mysql"</code>, <code>"rds-oracle"</code>, <code>"rds-sql-server"</code>, and <code>"rds-postgresql"</code>.</p>
    pub fn engine_name(&self) -> ::std::option::Option<&str> {
        self.engine_name.as_deref()
    }
    /// <p>The name of the limitation. Describes unsupported database features, migration action items, and other limitations.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the limitation. Provides additional information about the limitation, and includes recommended actions that you can take to address or avoid this limitation.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The impact of the limitation. You can use this parameter to prioritize limitations that you want to address. Valid values include <code>"Blocker"</code>, <code>"High"</code>, <code>"Medium"</code>, and <code>"Low"</code>.</p>
    pub fn impact(&self) -> ::std::option::Option<&str> {
        self.impact.as_deref()
    }
    /// <p>The type of the limitation, such as action required, upgrade required, and limited feature.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
}
impl Limitation {
    /// Creates a new builder-style object to manufacture [`Limitation`](crate::types::Limitation).
    pub fn builder() -> crate::types::builders::LimitationBuilder {
        crate::types::builders::LimitationBuilder::default()
    }
}

/// A builder for [`Limitation`](crate::types::Limitation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LimitationBuilder {
    pub(crate) database_id: ::std::option::Option<::std::string::String>,
    pub(crate) engine_name: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) impact: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
}
impl LimitationBuilder {
    /// <p>The identifier of the source database.</p>
    pub fn database_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the source database.</p>
    pub fn set_database_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_id = input;
        self
    }
    /// <p>The identifier of the source database.</p>
    pub fn get_database_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_id
    }
    /// <p>The name of the target engine that Fleet Advisor should use in the target engine recommendation. Valid values include <code>"rds-aurora-mysql"</code>, <code>"rds-aurora-postgresql"</code>, <code>"rds-mysql"</code>, <code>"rds-oracle"</code>, <code>"rds-sql-server"</code>, and <code>"rds-postgresql"</code>.</p>
    pub fn engine_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target engine that Fleet Advisor should use in the target engine recommendation. Valid values include <code>"rds-aurora-mysql"</code>, <code>"rds-aurora-postgresql"</code>, <code>"rds-mysql"</code>, <code>"rds-oracle"</code>, <code>"rds-sql-server"</code>, and <code>"rds-postgresql"</code>.</p>
    pub fn set_engine_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_name = input;
        self
    }
    /// <p>The name of the target engine that Fleet Advisor should use in the target engine recommendation. Valid values include <code>"rds-aurora-mysql"</code>, <code>"rds-aurora-postgresql"</code>, <code>"rds-mysql"</code>, <code>"rds-oracle"</code>, <code>"rds-sql-server"</code>, and <code>"rds-postgresql"</code>.</p>
    pub fn get_engine_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_name
    }
    /// <p>The name of the limitation. Describes unsupported database features, migration action items, and other limitations.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the limitation. Describes unsupported database features, migration action items, and other limitations.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the limitation. Describes unsupported database features, migration action items, and other limitations.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the limitation. Provides additional information about the limitation, and includes recommended actions that you can take to address or avoid this limitation.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the limitation. Provides additional information about the limitation, and includes recommended actions that you can take to address or avoid this limitation.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the limitation. Provides additional information about the limitation, and includes recommended actions that you can take to address or avoid this limitation.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The impact of the limitation. You can use this parameter to prioritize limitations that you want to address. Valid values include <code>"Blocker"</code>, <code>"High"</code>, <code>"Medium"</code>, and <code>"Low"</code>.</p>
    pub fn impact(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.impact = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The impact of the limitation. You can use this parameter to prioritize limitations that you want to address. Valid values include <code>"Blocker"</code>, <code>"High"</code>, <code>"Medium"</code>, and <code>"Low"</code>.</p>
    pub fn set_impact(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.impact = input;
        self
    }
    /// <p>The impact of the limitation. You can use this parameter to prioritize limitations that you want to address. Valid values include <code>"Blocker"</code>, <code>"High"</code>, <code>"Medium"</code>, and <code>"Low"</code>.</p>
    pub fn get_impact(&self) -> &::std::option::Option<::std::string::String> {
        &self.impact
    }
    /// <p>The type of the limitation, such as action required, upgrade required, and limited feature.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the limitation, such as action required, upgrade required, and limited feature.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of the limitation, such as action required, upgrade required, and limited feature.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`Limitation`](crate::types::Limitation).
    pub fn build(self) -> crate::types::Limitation {
        crate::types::Limitation {
            database_id: self.database_id,
            engine_name: self.engine_name,
            name: self.name,
            description: self.description,
            impact: self.impact,
            r#type: self.r#type,
        }
    }
}
