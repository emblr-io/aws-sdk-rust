// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The reference that identifies an object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectReference {
    /// <p>A path selector supports easy selection of an object by the parent/child links leading to it from the directory root. Use the link names from each parent/child link to construct the path. Path selectors start with a slash (/) and link names are separated by slashes. For more information about paths, see <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html">Access Objects</a>. You can identify an object in one of the following ways:</p>
    /// <ul>
    /// <li>
    /// <p><i>$ObjectIdentifier</i> - An object identifier is an opaque string provided by Amazon Cloud Directory. When creating objects, the system will provide you with the identifier of the created object. An object’s identifier is immutable and no two objects will ever share the same object identifier. To identify an object with ObjectIdentifier, the ObjectIdentifier must be wrapped in double quotes.</p></li>
    /// <li>
    /// <p><i>/some/path</i> - Identifies the object based on path</p></li>
    /// <li>
    /// <p><i>#SomeBatchReference</i> - Identifies the object in a batch call</p></li>
    /// </ul>
    pub selector: ::std::option::Option<::std::string::String>,
}
impl ObjectReference {
    /// <p>A path selector supports easy selection of an object by the parent/child links leading to it from the directory root. Use the link names from each parent/child link to construct the path. Path selectors start with a slash (/) and link names are separated by slashes. For more information about paths, see <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html">Access Objects</a>. You can identify an object in one of the following ways:</p>
    /// <ul>
    /// <li>
    /// <p><i>$ObjectIdentifier</i> - An object identifier is an opaque string provided by Amazon Cloud Directory. When creating objects, the system will provide you with the identifier of the created object. An object’s identifier is immutable and no two objects will ever share the same object identifier. To identify an object with ObjectIdentifier, the ObjectIdentifier must be wrapped in double quotes.</p></li>
    /// <li>
    /// <p><i>/some/path</i> - Identifies the object based on path</p></li>
    /// <li>
    /// <p><i>#SomeBatchReference</i> - Identifies the object in a batch call</p></li>
    /// </ul>
    pub fn selector(&self) -> ::std::option::Option<&str> {
        self.selector.as_deref()
    }
}
impl ObjectReference {
    /// Creates a new builder-style object to manufacture [`ObjectReference`](crate::types::ObjectReference).
    pub fn builder() -> crate::types::builders::ObjectReferenceBuilder {
        crate::types::builders::ObjectReferenceBuilder::default()
    }
}

/// A builder for [`ObjectReference`](crate::types::ObjectReference).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectReferenceBuilder {
    pub(crate) selector: ::std::option::Option<::std::string::String>,
}
impl ObjectReferenceBuilder {
    /// <p>A path selector supports easy selection of an object by the parent/child links leading to it from the directory root. Use the link names from each parent/child link to construct the path. Path selectors start with a slash (/) and link names are separated by slashes. For more information about paths, see <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html">Access Objects</a>. You can identify an object in one of the following ways:</p>
    /// <ul>
    /// <li>
    /// <p><i>$ObjectIdentifier</i> - An object identifier is an opaque string provided by Amazon Cloud Directory. When creating objects, the system will provide you with the identifier of the created object. An object’s identifier is immutable and no two objects will ever share the same object identifier. To identify an object with ObjectIdentifier, the ObjectIdentifier must be wrapped in double quotes.</p></li>
    /// <li>
    /// <p><i>/some/path</i> - Identifies the object based on path</p></li>
    /// <li>
    /// <p><i>#SomeBatchReference</i> - Identifies the object in a batch call</p></li>
    /// </ul>
    pub fn selector(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.selector = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A path selector supports easy selection of an object by the parent/child links leading to it from the directory root. Use the link names from each parent/child link to construct the path. Path selectors start with a slash (/) and link names are separated by slashes. For more information about paths, see <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html">Access Objects</a>. You can identify an object in one of the following ways:</p>
    /// <ul>
    /// <li>
    /// <p><i>$ObjectIdentifier</i> - An object identifier is an opaque string provided by Amazon Cloud Directory. When creating objects, the system will provide you with the identifier of the created object. An object’s identifier is immutable and no two objects will ever share the same object identifier. To identify an object with ObjectIdentifier, the ObjectIdentifier must be wrapped in double quotes.</p></li>
    /// <li>
    /// <p><i>/some/path</i> - Identifies the object based on path</p></li>
    /// <li>
    /// <p><i>#SomeBatchReference</i> - Identifies the object in a batch call</p></li>
    /// </ul>
    pub fn set_selector(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.selector = input;
        self
    }
    /// <p>A path selector supports easy selection of an object by the parent/child links leading to it from the directory root. Use the link names from each parent/child link to construct the path. Path selectors start with a slash (/) and link names are separated by slashes. For more information about paths, see <a href="https://docs.aws.amazon.com/clouddirectory/latest/developerguide/directory_objects_access_objects.html">Access Objects</a>. You can identify an object in one of the following ways:</p>
    /// <ul>
    /// <li>
    /// <p><i>$ObjectIdentifier</i> - An object identifier is an opaque string provided by Amazon Cloud Directory. When creating objects, the system will provide you with the identifier of the created object. An object’s identifier is immutable and no two objects will ever share the same object identifier. To identify an object with ObjectIdentifier, the ObjectIdentifier must be wrapped in double quotes.</p></li>
    /// <li>
    /// <p><i>/some/path</i> - Identifies the object based on path</p></li>
    /// <li>
    /// <p><i>#SomeBatchReference</i> - Identifies the object in a batch call</p></li>
    /// </ul>
    pub fn get_selector(&self) -> &::std::option::Option<::std::string::String> {
        &self.selector
    }
    /// Consumes the builder and constructs a [`ObjectReference`](crate::types::ObjectReference).
    pub fn build(self) -> crate::types::ObjectReference {
        crate::types::ObjectReference { selector: self.selector }
    }
}
