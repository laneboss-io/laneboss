package eventstore

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// ReadRunUsage reads a bounded prefix of the recorded run's byte interval.
// Display callers use ReadRunUsageContext to expose partial/capped statistics.
// Neither reader opens paths supplied by a vendor stream.
func ReadRunUsage(c *Configuration, lane, launch string) ([]Object, bool, error) {
	result, err := ReadRunUsageContext(context.Background(), c, lane, launch, nil)
	return result.Records, result.Available, err
}

func ReadRunUsageContext(ctx context.Context, c *Configuration, lane, launch string, cache *UsageCache) (RunUsage, error) {
	if !laneGrammar.MatchString(lane) || !storeIDGrammar.MatchString(launch) {
		return RunUsage{}, Refuse("invalid usage run")
	}
	if err := ctx.Err(); err != nil {
		return RunUsage{}, err
	}
	release, err := cache.enter(ctx, c.StatePath+"/"+lane+"/"+launch)
	if err != nil {
		return RunUsage{}, err
	}
	defer release()
	d, err := c.OpenDirectory(false)
	if err != nil || d == nil {
		return RunUsage{}, err
	}
	defer d.Close()
	data, err := d.ReadLane(lane, "runs", launch+".json", 4*1024*1024)
	if err != nil {
		return RunUsage{}, err
	}
	if data == nil {
		return RunUsage{Records: []Object{}}, nil
	}
	value, err := Parse(data, "the recorded run")
	if err != nil || object(value)["launch"] != launch {
		return RunUsage{}, Integrity("the usage run record is invalid")
	}
	span := object(object(value)["log"])
	start, ok := integerValue(span["start"])
	if !ok || start < 0 {
		return RunUsage{Records: []Object{}}, nil
	}
	path := filepath.Join("lanes", lane, "output.log")
	if _, err = checkedBelow(d.Path, path); os.IsNotExist(err) {
		return RunUsage{Records: []Object{}}, nil
	} else if err != nil {
		return RunUsage{}, err
	}
	root, err := os.OpenRoot(d.Path)
	if err != nil {
		return RunUsage{}, err
	}
	defer root.Close()
	identity, err := root.Stat(".")
	if err != nil || !os.SameFile(identity, d.identity) {
		return RunUsage{}, Integrity("the usage state directory changed")
	}
	file, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return RunUsage{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return RunUsage{}, Integrity("the usage log is not a regular file")
	}
	end := info.Size()
	if span["end"] != nil {
		end, ok = integerValue(span["end"])
		if !ok {
			return RunUsage{}, Integrity("the usage log interval is invalid")
		}
	}
	if start > end || end > info.Size() {
		return RunUsage{}, Integrity("the recorded usage log was truncated")
	}
	key := c.StatePath + "/" + lane + "/" + launch
	if result, hit, err := cache.get(ctx, key, info, start, end); hit || err != nil {
		return result, err
	}
	length := min(end-start, int64(MaxUsageBytes))
	result, err := scanRunUsage(ctx, io.NewSectionReader(file, start, length), length < end-start)
	if err != nil {
		return RunUsage{}, err
	}
	if err = cache.put(ctx, key, info, start, end, result); err != nil {
		return RunUsage{}, err
	}
	return result, nil
}
