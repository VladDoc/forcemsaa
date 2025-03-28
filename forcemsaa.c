/*
 * Derivative of https://github.com/dscharrer/void/blob/80a0281f18dd8d32db8ceb5e7db31f4c8af096f6/hacks/forcemsaa.c
 * ported to modern lineks
 * usage: LD_PRELOAD=forcemsaa.so your_gaem
 */
 
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <dlfcn.h>
#include <link.h>

#include <GL/glx.h>
#include <GL/gl.h>

int FORCE_MSAA_SAMPLES; // 4
int PREVENT_MSAA_GLDISABLE; // 0

static void read_config()
{
	FORCE_MSAA_SAMPLES = 4;
	PREVENT_MSAA_GLDISABLE = 0;
	
	FILE* config = fopen("./msaaconfig", "r");
	if(!config)
		return;
	
	fscanf(config, "FORCE_MSAA_SAMPLES: %d", &FORCE_MSAA_SAMPLES);
	fscanf(config, "PREVENT_MSAA_GLDISABLE: %d", &PREVENT_MSAA_GLDISABLE);
	PREVENT_MSAA_GLDISABLE = !!PREVENT_MSAA_GLDISABLE;
	
	fclose(config);
}

typedef void(*funcptr_t)();
typedef funcptr_t (*glXGetProcAddress_t)(const GLubyte* procName);
static glXGetProcAddress_t real_glXGetProcAddress;

static void* get_proc(const char* name) 
{
	if(!real_glXGetProcAddress)
		return NULL;
	
	return real_glXGetProcAddress((const GLubyte *)name);
}

typedef XVisualInfo* (*glXChooseVisual_t)
	(Display * dpy, int screen, int * attrib_list);

typedef GLXFBConfig* (*glXChooseFBConfig_t)
	(Display * dpy, int screen, const int * attrib_list, int * nelements);


static int has_value(int fbconfig, int attrib) 
{
	if(fbconfig)
		return 1;
	
	switch(attrib) {
		case GLX_USE_GL:
		case GLX_RGBA:
		case GLX_DOUBLEBUFFER:
		case GLX_STEREO:
		case GLX_FRAMEBUFFER_SRGB_CAPABLE_ARB:
			return 0;
		case GLX_BUFFER_SIZE:
		case GLX_LEVEL:
		case GLX_AUX_BUFFERS:
		case GLX_RED_SIZE:
		case GLX_GREEN_SIZE:
		case GLX_BLUE_SIZE:
		case GLX_ALPHA_SIZE:
		case GLX_DEPTH_SIZE:
		case GLX_STENCIL_SIZE:
		case GLX_ACCUM_RED_SIZE:
		case GLX_ACCUM_GREEN_SIZE:
		case GLX_ACCUM_BLUE_SIZE:
		case GLX_ACCUM_ALPHA_SIZE:
		case GLX_X_VISUAL_TYPE:
		case GLX_CONFIG_CAVEAT:
		case GLX_TRANSPARENT_TYPE:
		case GLX_TRANSPARENT_INDEX_VALUE:
		case GLX_TRANSPARENT_RED_VALUE:
		case GLX_TRANSPARENT_GREEN_VALUE:
		case GLX_TRANSPARENT_BLUE_VALUE:
		case GLX_TRANSPARENT_ALPHA_VALUE:
		case GLX_DRAWABLE_TYPE:
		case GLX_RENDER_TYPE:
		case GLX_SAMPLE_BUFFERS:
		case GLX_SAMPLES:
			return 1;
	}
	
	fprintf(stderr, LOG_PREFIX "!! unsupported glXChooseVisual attrib: 0x%x\n", attrib);
	return 0; // lets hope that if there is a value, it doesn match a known attrib
}

static int* fix_attrib_list(const int* attrib_list, int fbconfig) 
{
	int count = 0;
	while(attrib_list[count] != None) {
		count += 1 + has_value(fbconfig, attrib_list[count]);
	}
	
	int* new_attrib_list = malloc(sizeof(int) * (count + 1 + 4));
	if(!new_attrib_list)
		return NULL;
	
	int out = 0;
	for(int i = 0; attrib_list[i] != None; ) {
		if(attrib_list[i] == GLX_SAMPLE_BUFFERS || attrib_list[i] == GLX_SAMPLES) {
			// Ignore values requested by the program.
			// (Unity sets GLX_DONT_CARE for both of these.)
			i += 2;
		} else {
			if(has_value(fbconfig, attrib_list[i])) {
				new_attrib_list[out++] = attrib_list[i++];
			}
			new_attrib_list[out++] = attrib_list[i++];
		}
	}
	new_attrib_list[out++] = GLX_SAMPLE_BUFFERS;
	new_attrib_list[out++] = 1;
	new_attrib_list[out++] = GLX_SAMPLES;
	new_attrib_list[out++] = FORCE_MSAA_SAMPLES;
	new_attrib_list[out++] = None;
	
	return new_attrib_list;
}

// This is only needed for older (pre-GLX 1.4) clients
static XVisualInfo* redir_glXChooseVisual(Display* dpy, int screen, int* attrib_list)
{
	glXChooseVisual_t real_glXChooseVisual = get_proc("glXChooseVisual");
	if(!real_glXChooseVisual) {
		fprintf(stderr, LOG_PREFIX "!! could not get real glXChooseVisual\n");
		return NULL;
	}
	
	int* new_attrib_list = fix_attrib_list(attrib_list, 0);
	if(!new_attrib_list)
		return NULL;
	
	fprintf(stderr, LOG_PREFIX "injected MSAA config for glXChooseVisual\n");
	
	XVisualInfo* ret = real_glXChooseVisual(dpy, screen, new_attrib_list);
	
	free(new_attrib_list);
	
	return ret;
}

XVisualInfo* glXChooseVisual(Display* dpy, int screen, int* attrib_list)
{
	return redir_glXChooseVisual(dpy, screen, attrib_list);
}

static GLXFBConfig* 
redir_glXChooseFBConfig(Display* dpy, int screen, const int* attrib_list, int* nelements)
{
	glXChooseFBConfig_t real_glXChooseFBConfig = get_proc("glXChooseFBConfig");
	if(!real_glXChooseFBConfig) {
		fprintf(stderr, LOG_PREFIX "!! could not get real glXChooseFBConfig\n");
		*nelements = 0;
		return NULL;
	}
	
	int* new_attrib_list = fix_attrib_list(attrib_list, 1);
	if(!new_attrib_list) {
		*nelements = 0;
		return NULL;
	}
	
	fprintf(stderr, LOG_PREFIX "injected MSAA config for glXChooseFBConfig\n");
	
	GLXFBConfig* ret = real_glXChooseFBConfig(dpy, screen, new_attrib_list, nelements);
	
	free(new_attrib_list);
	
	return ret;
}

GLXFBConfig* 
glXChooseFBConfig(Display* dpy, int screen, const int* attrib_list, int* nelements)
{
	return redir_glXChooseFBConfig(dpy, screen, attrib_list, nelements);
}

typedef void (*glDisable_t)(GLenum value);

// This is only needed for older (pre-GLX 1.4) clients
static void redir_glDisable(GLenum value) 
{
	if(PREVENT_MSAA_GLDISABLE && value == GL_MULTISAMPLE) {
		return;
	}
	
	glDisable_t real_glDisable = get_proc("glDisable");
	if(real_glDisable)
		real_glDisable(value);
}

void glDisable(GLenum value) 
{
	redir_glDisable(value);
}

// Hooking boilerplate code follows
typedef void* (*dlsym_t)(void* handle, const char* name);
static dlsym_t real_dlsym;

typedef void* (*dlvsym_t)(void* handle, const char* symbol, const char* version);
static dlvsym_t real_dlvsym;

static glXGetProcAddress_t real_glXGetProcAddressARB;

typedef struct {
	ElfW(Word) nbucket;
	ElfW(Word) nchain;
	ElfW(Word) bucket[];
} dt_hash_t;

const char* target_libs[3] = {
	"libdl.so",
	"libc.so",
	NULL
};

unsigned long elf_Hash(const unsigned char *name) 
{
	unsigned long h = 0, g;

	while (*name) {
		h = (h << 4) + *name++;
		if ((g = h & 0xf0000000))
		h ^= g >> 24;
		h &= ~g;
	}
	return h;
}

int sanity_check(struct dl_phdr_info *info, ElfW(Addr) address)
{
	for (int i = 0; i < info->dlpi_phnum; ++i) {
		ElfW(Addr) start, end;
		start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
		end = start + info->dlpi_phdr[i].p_memsz;

		if (info->dlpi_phdr[i].p_type == PT_LOAD) {
			if (address >= start && address < end) {
				return 0;
			}
		}
	}
	return 1;
}

static int callback(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size; (void)data;
	for (int i = 0; i < info->dlpi_phnum; ++i) {
		ElfW(Word) dt_soname = 0;
		char *dt_strtab = NULL;
		ElfW(Sym) *dt_symtab = NULL;
		dt_hash_t *dt_hash = NULL;

		if (info->dlpi_phdr[i].p_type != PT_DYNAMIC) {
			continue;
		}

		ElfW(Dyn) *dyn = (ElfW(Dyn)*)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
		for (; dyn->d_tag != DT_NULL; ++dyn) {
			switch(dyn->d_tag) {
				case DT_SYMTAB:
					dt_symtab = (ElfW(Sym)*)dyn->d_un.d_ptr;
					break;
				case DT_SONAME:
					dt_soname = (ElfW(Word))dyn->d_un.d_val;
					break;
				case DT_STRTAB:
					dt_strtab = (char*)dyn->d_un.d_ptr;
					break;
				case DT_HASH:
					dt_hash = (dt_hash_t*)(dyn->d_un.d_ptr);
					break;
				default:
					break;
			}
		}

		if (dt_strtab == NULL || dt_soname == 0) {
			return 0;
		}
		if (sanity_check(info, (ElfW(Addr))dt_strtab) != 0) {
			return 0; // broken header
		}

		for (int l = 0; ; ++l) {
			if (target_libs[l] == NULL) {
				return 0;
			}

			if (strstr(dt_strtab + dt_soname, target_libs[l]) != NULL) {
				break;
			}
		}

		if (dt_hash == NULL || dt_symtab == NULL) {
			return 0;
		}
		if (sanity_check(info, (ElfW(Addr))dt_hash) != 0 || sanity_check(info, (ElfW(Addr))dt_symtab) != 0) {
			return 0; // broken header
		}

		unsigned long dlsym_hash = elf_Hash((unsigned char*)"dlsym");
		ElfW(Word) y = dt_hash->bucket[dlsym_hash % dt_hash->nbucket];
		if (strcmp(dt_strtab + dt_symtab[y].st_name, "dlsym") != 0) {
			y = dt_hash->bucket[y + dt_hash->nbucket];
			while (dt_symtab[y].st_value != STN_UNDEF) {
				if (strcmp(dt_strtab + dt_symtab[y].st_name, "dlsym") == 0) {
					break;
				}
				++y;
			}
		}
		if (dt_symtab[y].st_value != STN_UNDEF) {
			real_dlsym = (void *(*)( void*, const char* ))(dt_symtab[y].st_value + info->dlpi_addr);
			return 1;
		}
	}
	return 0;
}

static void* find_dlsym()
{
	dl_iterate_phdr(callback, NULL);
	return real_dlsym;
}

static void hook_init(void) __attribute__((constructor));
static void hook_init(void) {
	real_dlsym = find_dlsym();
	read_config();

	if(!real_dlsym)
		return;
		
	// Get the dlsym from any LD_PRELOAD library loaded before us
	void* ptr = real_dlsym(RTLD_NEXT, "dlsym");
	if(ptr) real_dlsym = (dlsym_t)ptr;
	// Get other overwritten symbols
	real_dlvsym = real_dlsym(RTLD_NEXT, "dlvsym");
	
	void* libglx = dlopen("libGLX.so", RTLD_LAZY);
	if(!libglx)
		return;
	
	real_glXGetProcAddress = real_dlsym(libglx, "glXGetProcAddress");
	real_glXGetProcAddressARB = real_dlsym(libglx, "glXGetProcAddressARB");
	if(!real_glXGetProcAddress)
		real_glXGetProcAddress = real_glXGetProcAddressARB;
}

static void* hook_dlsym(const char* name, const char* hook);

static void* redir_dlsym(void* handle, const char* name)
{
	void* ptr = hook_dlsym(name, "dlsym");
	if(ptr)
		return ptr;
	
	if(!real_dlsym)
		return NULL;
		
	return real_dlsym(handle, name);
}
void* dlsym(void* handle, const char* name) 
{
	return redir_dlsym(handle, name);
}

static void* redir_dlvsym(void* handle, const char* symbol, const char* version)
{
	void* ptr = hook_dlsym(symbol, "dlvsym");
	if(ptr)
		return ptr;
	
	if(real_dlvsym)
		return real_dlvsym(handle, symbol, version);
	
	return NULL;
}
void* dlvsym(void* handle, const char* symbol, const char* version)
{
	return redir_dlvsym(handle, symbol, version);
}

static funcptr_t redir_glXGetProcAddress(const GLubyte* procName)
{
	void* ptr = hook_dlsym((const char*)procName, "glXGetProcAddress");
	if(ptr)
		return (funcptr_t)ptr;
	
	if(real_glXGetProcAddress)
		return real_glXGetProcAddress(procName);
		
	return NULL;
}
funcptr_t glXGetProcAddress(const GLubyte* procName)
{
	return redir_glXGetProcAddress(procName);
}

static funcptr_t redir_glXGetProcAddressARB(const GLubyte* procName)
{
	void* ptr = hook_dlsym((const char *)procName, "glXGetProcAddressARB");
	if(ptr)
		return (funcptr_t)ptr;
	
	if(real_glXGetProcAddressARB)
		return real_glXGetProcAddressARB(procName);
	if(real_glXGetProcAddress)
		return real_glXGetProcAddress(procName);
	
	return NULL;
}

funcptr_t glXGetProcAddressARB(const GLubyte* procName)
{
	return redir_glXGetProcAddressARB(procName);
}

static void* hook_dlsym(const char* name, const char* hook)
{
	if(!name)
		return NULL;
	if(!strcmp(name, "glXChooseVisual")) {
		fprintf(stderr, LOG_PREFIX "hooked %s via %s\n", name, hook);
		return (void *)redir_glXChooseVisual;
	}
	if(!strcmp(name, "glXChooseFBConfig")) {
		fprintf(stderr, LOG_PREFIX "hooked %s via %s\n", name, hook);
		return (void *)redir_glXChooseFBConfig;
	}
	if(PREVENT_MSAA_GLDISABLE && !strcmp(name, "glDisable")) {
		fprintf(stderr, LOG_PREFIX "hooked %s via %s\n", name, hook);
		return (void *)redir_glDisable;
	}
	if(!strcmp(name, "dlsym")) {
		return (void *)redir_dlsym;
	}
	if(!strcmp(name, "dlvsym")) {
		return (void *)redir_dlvsym;
	}
	if(!strcmp(name, "glXGetProcAddress")) {
		return (void *)redir_glXGetProcAddress;
	}
	if(!strcmp(name, "glXGetProcAddressARB")) {
		return (void *)redir_glXGetProcAddressARB;
	}
	return NULL;
}
