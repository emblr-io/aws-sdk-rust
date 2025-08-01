// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The value of an attribute.</p>
/// <p>Contains information about the runtime context for a request for which an authorization decision is made.</p>
/// <p>This data type is used as a member of the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ContextDefinition.html">ContextDefinition</a> structure which is uses as a request parameter for the <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorized.html">IsAuthorized</a>, <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_BatchIsAuthorized.html">BatchIsAuthorized</a>, and <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_IsAuthorizedWithToken.html">IsAuthorizedWithToken</a> operations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub enum AttributeValue {
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#boolean">Boolean</a> type.</p>
    /// <p>Example: <code>{"boolean": true}</code></p>
    Boolean(bool),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#datatype-decimal">decimal</a> type.</p>
    /// <p>Example: <code>{"decimal": "1.1"}</code></p>
    Decimal(::std::string::String),
    /// <p>An attribute value of type <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_EntityIdentifier.html">EntityIdentifier</a>.</p>
    /// <p>Example: <code>"entityIdentifier": { "entityId": "&lt;id&gt;", "entityType": "&lt;entity type&gt;"}</code></p>
    EntityIdentifier(crate::types::EntityIdentifier),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#datatype-ipaddr">ipaddr</a> type.</p>
    /// <p>Example: <code>{"ip": "192.168.1.100"}</code></p>
    Ipaddr(::std::string::String),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#long">Long</a> type.</p>
    /// <p>Example: <code>{"long": 0}</code></p>
    Long(i64),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#record">Record</a> type.</p>
    /// <p>Example: <code>{"record": { "keyName": {} } }</code></p>
    Record(::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#set">Set</a> type.</p>
    /// <p>Example: <code>{"set": \[ {} \] }</code></p>
    Set(::std::vec::Vec<crate::types::AttributeValue>),
    /// <p>An attribute value of <a href="https://docs.cedarpolicy.com/policies/syntax-datatypes.html#string">String</a> type.</p>
    /// <p>Example: <code>{"string": "abc"}</code></p>
    String(::std::string::String),
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
impl AttributeValue {
    /// Tries to convert the enum instance into [`Boolean`](crate::types::AttributeValue::Boolean), extracting the inner [`bool`](bool).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_boolean(&self) -> ::std::result::Result<&bool, &Self> {
        if let AttributeValue::Boolean(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Boolean`](crate::types::AttributeValue::Boolean).
    pub fn is_boolean(&self) -> bool {
        self.as_boolean().is_ok()
    }
    /// Tries to convert the enum instance into [`Decimal`](crate::types::AttributeValue::Decimal), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_decimal(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let AttributeValue::Decimal(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Decimal`](crate::types::AttributeValue::Decimal).
    pub fn is_decimal(&self) -> bool {
        self.as_decimal().is_ok()
    }
    /// Tries to convert the enum instance into [`EntityIdentifier`](crate::types::AttributeValue::EntityIdentifier), extracting the inner [`EntityIdentifier`](crate::types::EntityIdentifier).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_entity_identifier(&self) -> ::std::result::Result<&crate::types::EntityIdentifier, &Self> {
        if let AttributeValue::EntityIdentifier(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`EntityIdentifier`](crate::types::AttributeValue::EntityIdentifier).
    pub fn is_entity_identifier(&self) -> bool {
        self.as_entity_identifier().is_ok()
    }
    /// Tries to convert the enum instance into [`Ipaddr`](crate::types::AttributeValue::Ipaddr), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_ipaddr(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let AttributeValue::Ipaddr(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Ipaddr`](crate::types::AttributeValue::Ipaddr).
    pub fn is_ipaddr(&self) -> bool {
        self.as_ipaddr().is_ok()
    }
    /// Tries to convert the enum instance into [`Long`](crate::types::AttributeValue::Long), extracting the inner [`i64`](i64).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_long(&self) -> ::std::result::Result<&i64, &Self> {
        if let AttributeValue::Long(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Long`](crate::types::AttributeValue::Long).
    pub fn is_long(&self) -> bool {
        self.as_long().is_ok()
    }
    /// Tries to convert the enum instance into [`Record`](crate::types::AttributeValue::Record), extracting the inner [`HashMap`](::std::collections::HashMap).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_record(&self) -> ::std::result::Result<&::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>, &Self> {
        if let AttributeValue::Record(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Record`](crate::types::AttributeValue::Record).
    pub fn is_record(&self) -> bool {
        self.as_record().is_ok()
    }
    /// Tries to convert the enum instance into [`Set`](crate::types::AttributeValue::Set), extracting the inner [`Vec`](::std::vec::Vec).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_set(&self) -> ::std::result::Result<&::std::vec::Vec<crate::types::AttributeValue>, &Self> {
        if let AttributeValue::Set(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`Set`](crate::types::AttributeValue::Set).
    pub fn is_set(&self) -> bool {
        self.as_set().is_ok()
    }
    /// Tries to convert the enum instance into [`String`](crate::types::AttributeValue::String), extracting the inner [`String`](::std::string::String).
    /// Returns `Err(&Self)` if it can't be converted.
    pub fn as_string(&self) -> ::std::result::Result<&::std::string::String, &Self> {
        if let AttributeValue::String(val) = &self {
            ::std::result::Result::Ok(val)
        } else {
            ::std::result::Result::Err(self)
        }
    }
    /// Returns true if this is a [`String`](crate::types::AttributeValue::String).
    pub fn is_string(&self) -> bool {
        self.as_string().is_ok()
    }
    /// Returns true if the enum instance is the `Unknown` variant.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}
impl ::std::fmt::Debug for AttributeValue {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        match self {
            AttributeValue::Boolean(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            AttributeValue::Decimal(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            AttributeValue::EntityIdentifier(val) => f.debug_tuple("EntityIdentifier").field(&val).finish(),
            AttributeValue::Ipaddr(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            AttributeValue::Long(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            AttributeValue::Record(val) => f.debug_tuple("Record").field(&val).finish(),
            AttributeValue::Set(val) => f.debug_tuple("Set").field(&val).finish(),
            AttributeValue::String(_) => f.debug_tuple("*** Sensitive Data Redacted ***").finish(),
            AttributeValue::Unknown => f.debug_tuple("Unknown").finish(),
        }
    }
}
