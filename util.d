module util;

import d_etpan;
import std.stdio;
import std.string;
import std.file;
import std.conv;
import core.memory;
import core.stdc.stdlib:free;
import std.exception;

     
enum DEST_CHARSET "iso-8859-1";

alias parsedEmail = Tuple!(string,"mailbox",string, "host");
alias Mailbox = Tuple!(string, "name", string, "route",string, "mailbox",string, "host");
alias ImapResponse = Tuple!(string, "completion", string, "route",string, "mailbox",string, "host");

struct MailingGroup
{
	string name;
	Mailbox[] mailboxes;

	string toString()
	{
		string ret;
		ret=this.name~": "~toString(this.mailboxes)~";";
		return ret;
	}
}

enum AddressType
{
	Mailbox,
	MailingGroup
}

struct Address
{
	AddressType atype;
	union AddressData
	{
		MailingGroup mailingGroup;
		Mailbox mailbox;
	}
	AddressData data;

	string toString()
	{
		if (this.atype==AddressType.Mailbox)
		{
			return toString(this.data.mailbox);
		}
		else if (this.atype==AddressType.MailingGroup)
		{
			return toString(this.data.mailingGroup);
		}
		else
		{
			throw new EmailException(EmailException.Kind.error, "EmailClient: unknown address type: "~ this.atype);
		}
	}
}

string ZtoString(const char* c)
{
    if (c !is null)
      return to!string(fromStringz(c));
    else
      return null;
}

char* toZString(string s)
{
	char[] ret=cast(char[])s;
	if (ret[$-1]!='\0')
		ret~="\0";
	return ret.ptr;
}
/* returns TRUE is given MIME part is a text part */

bool isNull(T)(T ptr)
{
  return (ptr==cast(T)(0));
}

class EmailException:Exception
{
  this(string msg)
  {
    super(msg);
  }
  this(Kind kind, string message)
  {
    this.kind=kind;
    this.error=message;
    if (kind==Kind.errno)
      this.errno=core.stdc.errno.errno;
    super(message);
  }

  this(Kind kind, string message, int r)
  {
    this.kind=kind;
    this.error=message;
    if (kind==Kind.errno)
      this.errno=core.stdc.errno.errno;
 	else if ((kind==Kind.libetpan_error) || (kind==Kind.libetpan_abort)||(kind==Kind.libetpan_readonly))
 		etpan=ZtoString(maildriver_strerror(r));
 	if (etpan.length==0)
    	super(message);
    else
    	super(message~"; etpan error="~etpan);
  }

  /*EmailException opCall(Kind kind, string message)
  {
    this.kind=kind;
    return this;
  }*/
  enum Kind
  {
    error,              //  General error
    errno,              //  Raised when call to C library leads to error described by errno
    args,
    libetpan_error,     //  Exception raised on any errors. The reason for the exception is passed to the constructor as a string.
    libetpan_abort,     //  IMAP4 server errors cause this exception to be raised.  reopening connection may allow recovery
    libetpan_readonly,  //  Raised when a writable mailbox has its status changed by the server
    libetpan_auth
  }
  Kind kind;
  string etpan;
  string error;
  int errno;
}

class EmailAuthException:EmailException
{
	this(string msg)
	{
		super(msg);
	}

	this(Kind kind, string message)
	{
		super(kind,message);
	}

	this(Kind kind,string message, int r)
	{
		super(kind,message,r);
	}
}

short getDefaultPort(string driver)
{
	driver=driver.toUpper();
	switch(driver)
	{
		case "IMAP":
			return 143;
		case "IMAPS":
			return 993;
		case "SMTP":
			return 587;
		case "POP":
			return 110;
		case "SSMTP":
			return 587;
		default:
			throw new EmailException(EmailException.Kind.argumenterror,"Unknown driver type: "~ driver~ " should be IMAP/IMAPS/SMTP/POP/SSMTP");
	}
	assert(0);
}

string[3] parseURI(string uri)
{
	string[3] ret;
	auto i=uri.indexOf("://");
	enforce(i>-1,new EmailException(EmailException.Kind.argumenterror,"URI malformed: should be eg imaps://mail.google.com or imaps://mail.google.com:123"));
	enforce((i+3)<uri.length,new EmailException(EmailException.Kind.argumenterror,"URI malformed: should be eg imaps://mail.google.com or imaps://mail.google.com:123"));
	ret[0]=uri[0..i];
	auto j=uri[i+3..$].indexOf(":");
	if (j==-1)
	{
		ret[1]=uri[i+3..$];
		ret[2]=to!string(getDefaultPort(ret[0]));
	}
	else
	{
		ret[1]=uri[i+3..i+3+j];
		ret[2]=uri[i+4+j..$];
	}
	enforce(to!short(ret[2])>0,new EmailException(EmailException.Kind.argumenterror,"URI malformed - invalid port="~ret[2]~": should be eg imaps://mail.google.com or imaps://mail.google.com:123"));
	return ret;
}

int auth_type(string auth,int protocol)
{
  auth=auth.toUpper();
  switch(auth)
  {
    case "TLS":
      return CONNECTION_TYPE_TLS;
    case "STARTTLS":
      return CONNECTION_TYPE_STARTTLS;
    case "APOP":
      if (protocol==POP3_STORAGE)
        return POP3_AUTH_TYPE_APOP;
      else
        break;
    default:
      throw new EmailException(EmailException.Kind.args, "Unknown connection type: "~auth));
  }
  throw new EmailException(EmailException.Kind.args, "Unknown connection type: "~auth));
}

DateTime ETtoDateTimeLocal(mailimf_date_time * d)
{
  return DateTime(d.dt_year,d.dt_month,dt.dt_day, d.dt_hour, d.dt_min, d.dt_sec);
}

DateTime ETtoDateTimeUTC(mailimf_date_time * d)
{
	return DateTime(d.dt_year,d.dt_month,dt.dt_day, d.dt_hour, d.dt_min, d.dt_sec).add!"minutes"(d.dt_zone);
}
// check the direction is right!


string fieldCaseCompare(string field, string[] matches)
{
  foreach(cmpField;matches)
  {
    if (field.toLower()==cmpField.toLower())
      return true;
  }
  return false;
}
string fieldCaseNCompare(string field, string[] matches)
{
  foreach(cmpField;matches)
  {
    if (field[0..max($,cmpField.length)].toLower==matches.toLower())
      return true;
  }
  return false;
}

void strip_crlf(ubyte[] str)
{
  char * p;
  
  for(p = str ; * p != '\0' ; p ++) {
	if ((* p == '\n') || (* p == '\r'))
	  * p = ' ';
  }
}

parsedEmail parseEmail(string email)
{
	auto i = email.indexOf("@");
	if ((i==-1) || ((i+2)>email.length))
		return parsedEmail(email);
	return parsedEmail(email[0..i],email[i+1..$]);
}


/**
	ETPAN lingo:
		an address can be either a mailbox or a group
		a mailbox is a name and email eg John Smith, john@smith.com
		a group is a group name and a list of mailboxes

We have the following functions:

	Mailbox mailboxFromET(mailimf_mailbox *mb)
	Address addressFromET(mailimf_address *address)
	mailimf_mailbox* makeETMailbox(Mailbox mailbox)
	mailimf_mailbox_list* makeETMailboxList(Mailbox[] mailboxes)
	Mailbox[] mailboxListFromET(mailimf_mailbox_list* mblist)
	mailimf_group* makeETGroup(MailingGroup mailingGroup)
	MailingGroup[] mailingGroupFromET(mailimf_group* mailimfgroup)
	mailimf_address_list *makeETAddressList(Address[] addresses)
	Address[] addressListFromET(mailimf_address_list * addressList)

*/		


Mailbox mailboxFromET(mailimf_mailbox *mb)
{
	auto email=parseEmail(ZtoString(mb.mb_addr_spec));
	return Mailbox(ZtoString(mb.mb_display_name),"",email.mailbox,email.host);
}


Address addressFromET(mailimf_address *address)
{
	Address ret;
	if (address is null)
		return ret;
	if (address.ad_type==MAILIMF_ADDRESS_MAILBOX)
	{
		ret.atype=AddressType.Mailbox;
		ret.data.Address.mailbox=mailboxFromET(address.ad_data.ad_mailbox);
	}
	else if (address.ad_type==MAILIMF_ADDRESS_GROUP)
	{
		ret.atype=AddressType.Group;
		ret.data.Address.mailingGroup=mailingGroupboxfromET(address.ad_data.ad_group);
	}
	else
	{
		throw new EmailException(EmailException.Kind.libetpan_error, 
			"EmailClient: etpanlib failed to make sense of email address - unknown type: "~address.ad_type);
	}
	return ret;
}

// watch out for garbage collector - might need to keep reference around to the mailbox struct (which also
// has reference to string

mailimf_mailbox* makeETMailbox(Mailbox mailbox)
{
	mb= new mailimf_mailbox;
	mb.mb_display_name=toZString(mailbox.name);
	mb.mb_addr_spec=toZString(mailbox.mailbox~"@"~mailbox.host);
	return &mb;
}


mailimf_mailbox_list* makeETMailboxList(Mailbox[] mailboxes)
{
	int r;
	mailimf_mailbox_list* mailBoxList;
    enforce((mailBoxList = mailimf_mailbox_list_new_empty())!is null,
		new EmailException(EmailException.Kind.libetpan_error, 
			"EmailClient: etpanlib failed to create empty mailbox list - memory error?");

    foreach(mailbox;mailboxes)
    {
		enforce((r=mailimf_mailbox_list_add_mb(mailBoxList,
			toZString(mailbox.name),toZString(mailbox.mailbox~"@"~mailbox.host)))==MAILIMF_NO_ERROR,
            new EmailException(EmailException.Kind.libetpan_error,
                  "EmailClient: etpanlib failed to add address "~mailbox.mailbox~"@"~mailbox.host~" to mailbox list",r));
  	}
  	return mailBoxList;
}

Mailbox[] mailboxListFromET(mailimf_mailbox_list* mblist)
{
	Mailbox[] ret;
    clistiter * cur;
    int r;
    int first=1;

    for(cur = clist_begin(mailBoxList.mb_list) ; (!isNull(cur)) ; cur = clist_next(cur))
    {
      mailimf_mailbox * mb=cast(mailimf_mailbox *)cur.data; // or mb=clist_content(cur); // no data
      ret~=addressFromEtMailbox(mailimf_mailbox);
    }
    return ret;
}

mailimf_group* makeETGroup(MailingGroup mailingGroup)
{
	mailimf_group * mg;
	grp_mb_list *list;
	enforce((list=makeETMailboxList(mailingGroup.mailboxes)) !is null,
		new EmailException(EmailException.Kind.libetpan_error, 
			"EmailClient: etpanlib failed to build list when creating email group " ~ mailingGroup.name~ ": memory error?");
	enforce((mg=mailimf_group_new(toZString(mailingGroup.name,list)) !is null,
		new EmailException(EmailException.Kind.libetpan_error,
        	"EmailClient: etpanlib failed to create email group "~ mailingGroup.name~": memory error?",r));
	return mg;
}

MailingGroup[] mailingGroupFromET(mailimf_group* mailimfgroup)
{
	MailingGroup mailingGroup;
    if !isNull(mailimfgroup)
    {
      MailingGroup.name=ZtoString(mailimfgroup.grp_display_name);
      MailingGroup.mailboxes=MailBoxListFromET(mailimfgroup.grp_mb_list);
    }
  	return MailingGroup;
}


mailimf_address_list *makeETAddressList(Address[] addresses)
{
	mailimf_address_list* addressList;

    enforce((addressList = mailimf_address_list_new_empty()) !is null,
		new EmailException(EmailException.Kind.libetpan_error,
			"EmailClient: etpanlib failed to create empty address list - memory error?");

    foreach(address;addresses)
    {
	      mailimf_address addr;
	      if (address.atype==AddressType.Mailbox)
	      {
	      	addr.ad_type=MAILIMF_ADDRESS_MAILBOX;
	      	addr.ad_mailbox=makeETMailbox(address.data.mailbox);
	      }
	      else if (address.atype==AddressType.MailingGroup)
	      {
	      	addr.ad_data.ad_type=MAILIMF_ADDRESS_GROUP;
	      	addr.ad_data.ad_group=makeETGroup(address.data.mailingGroup)
	      }
	 	  enforce((r=(mailimf_address_list_add_(addressList,toStringz(email)))==MAILIMF_NO_ERROR,
			new EmailException(EmailException.Kind.libetpan_error,
	        	"EmailClient: etpanlib failed to create address list: memory error?",r));
    }
	return addressList;
}

Address[] addressListFromET(mailimf_address_list * addressList)
{
	Address[] ret;

    clistiter * cur;
    int r;
    int first=1;

    for(cur = clist_begin(addressList) ; (!isNull(cur)) ; cur = clist_next(cur))
    {
		mailimf_address *address=cast(mailimf_address *)cur.data; // or mb=clist_content(cur); // no data
		ret~=addressFromET(address);
    }
    return ret;
}

string toString(Mailbox mailbox)
{
	return mailbox.name ~ "<"~ mailbox.mailbox~"@"~mailbox.host~">";
}

string toString(Mailbox[] mailboxes)
{
	int i=0;
	string ret;
	foreach(mailbox;mailboxes)
	{
		ret~=toString(mailbox)~",";
		i=1;
	}
	if (i==1)
		ret=ret[0..$-1];
	return ret;
}

